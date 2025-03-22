package xratelimit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(RateLimit{})
	httpcaddyfile.RegisterHandlerDirective("xratelimit", parseCaddyfile)
}

type RateLimit struct {
	RequestsPerSecond int      `json:"requests_per_second,omitempty"`
	BlockDuration     string   `json:"block_duration,omitempty"`
	WhitelistIPs      []string `json:"whitelist_ips,omitempty"`
	BlacklistIPs      []string `json:"blacklist_ips,omitempty"`
	BlockUserAgents   []string `json:"block_user_agents,omitempty"`
	BlockCountries    []string `json:"block_countries,omitempty"`
	BlockScanBots     bool     `json:"block_scan_bots,omitempty"`

	// Новые опции
	BlockReferers      []string             `json:"block_referers,omitempty"`
	IPRanges           []string             `json:"ip_ranges,omitempty"`
	AllowedMethods     []string             `json:"allowed_methods,omitempty"`
	DisallowedMethods  []string             `json:"disallowed_methods,omitempty"`
	RulesPerPath       map[string]*PathRule `json:"rules_per_path,omitempty"`
	LogLevel           string               `json:"log_level,omitempty"`
	CustomResponseCode int                  `json:"custom_response_code,omitempty"`
	BurstCapacity      int                  `json:"burst_capacity,omitempty"`
	EnableJSChallenge  bool                 `json:"enable_js_challenge,omitempty"`
	IPHashingKey       string               `json:"ip_hashing_key,omitempty"`
	BanAfterBlocks     int                  `json:"ban_after_blocks,omitempty"`
	BanDuration        string               `json:"ban_duration,omitempty"`
	TrustForwardedFor  bool                 `json:"trust_forwarded_for,omitempty"`
	ExportMetrics      bool                 `json:"export_metrics,omitempty"`
	MetricsPath        string               `json:"metrics_path,omitempty"`

	blockDuration     time.Duration
	banDuration       time.Duration
	logger            *zap.Logger
	visitors          map[string]*visitor
	whitelist         map[string]bool
	blacklist         map[string]bool
	whitelistRanges   []*net.IPNet
	blacklistRanges   []*net.IPNet
	blockUserAgentRE  []*regexp.Regexp
	blockRefererRE    []*regexp.Regexp
	countryBlocks     map[string]bool
	allowedMethods    map[string]bool
	disallowedMethods map[string]bool
	mu                sync.RWMutex

	stats struct {
		sync.RWMutex
		totalRequests       int64
		totalBlocked        int64
		totalWhitelisted    int64
		totalBlacklisted    int64
		totalBotBlocked     int64
		totalUABlocked      int64
		totalGeoBlocked     int64
		totalRefererBlocked int64
		totalMethodBlocked  int64
		totalPathBlocked    int64
		totalJSChallenges   int64
		totalJSFailed       int64
		requestsPerInterval map[string]int64
		blocksPerInterval   map[string]int64
		lastIntervalUpdate  time.Time
		topVisitors         map[string]int64
		blockReasons        map[string]int64
		pathHits            map[string]int64
		methodRequests      map[string]int64
	}
}

// PathRule определяет правила для определенного пути
type PathRule struct {
	Path              string   `json:"path"`
	RequestsPerSecond int      `json:"requests_per_second,omitempty"`
	BlockDuration     string   `json:"block_duration,omitempty"`
	WhitelistIPs      []string `json:"whitelist_ips,omitempty"`
	AllowedMethods    []string `json:"allowed_methods,omitempty"`
	DisallowedMethods []string `json:"disallowed_methods,omitempty"`
	BurstCapacity     int      `json:"burst_capacity,omitempty"`

	blockDuration     time.Duration
	whitelist         map[string]bool
	allowedMethods    map[string]bool
	disallowedMethods map[string]bool
}

type visitor struct {
	count       int
	lastSeen    time.Time
	blocked     bool
	blockedAt   time.Time
	unblockAt   time.Time
	requestIPs  []string
	userAgent   string
	country     string
	blockReason string
	burstTokens int
	totalBlocks int
	challenges  map[string]time.Time // map[challenge token]expiry time
	lastPaths   []string
	lastMethods []string
	referers    []string
}

func (RateLimit) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.xratelimit",
		New: func() caddy.Module { return new(RateLimit) },
	}
}

func (rl *RateLimit) Provision(ctx caddy.Context) error {
	rl.logger = ctx.Logger(rl)
	rl.visitors = make(map[string]*visitor)
	rl.whitelist = make(map[string]bool)
	rl.blacklist = make(map[string]bool)
	rl.countryBlocks = make(map[string]bool)
	rl.allowedMethods = make(map[string]bool)
	rl.disallowedMethods = make(map[string]bool)
	rl.whitelistRanges = make([]*net.IPNet, 0)
	rl.blacklistRanges = make([]*net.IPNet, 0)

	rl.stats.requestsPerInterval = make(map[string]int64)
	rl.stats.blocksPerInterval = make(map[string]int64)
	rl.stats.topVisitors = make(map[string]int64)
	rl.stats.blockReasons = make(map[string]int64)
	rl.stats.pathHits = make(map[string]int64)
	rl.stats.methodRequests = make(map[string]int64)
	rl.stats.lastIntervalUpdate = time.Now()

	if rl.RequestsPerSecond <= 0 {
		rl.RequestsPerSecond = 10
	}

	if rl.BlockDuration == "" {
		rl.BlockDuration = "5m"
	}

	if rl.BurstCapacity <= 0 {
		rl.BurstCapacity = rl.RequestsPerSecond * 2
	}

	if rl.BanAfterBlocks <= 0 {
		rl.BanAfterBlocks = 5
	}

	if rl.BanDuration == "" {
		rl.BanDuration = "24h"
	}

	if rl.LogLevel == "" {
		rl.LogLevel = "info"
	}

	if rl.CustomResponseCode <= 0 {
		rl.CustomResponseCode = http.StatusTooManyRequests
	}

	if rl.MetricsPath == "" {
		rl.MetricsPath = "/metrics"
	}

	// Инициализация IP белого и черного списков
	for _, ip := range rl.WhitelistIPs {
		if strings.Contains(ip, "/") {
			_, network, err := net.ParseCIDR(ip)
			if err != nil {
				rl.logger.Warn("Failed to parse CIDR for whitelist", zap.String("cidr", ip), zap.Error(err))
				continue
			}
			rl.whitelistRanges = append(rl.whitelistRanges, network)
		} else {
			rl.whitelist[ip] = true
		}
	}

	for _, ip := range rl.BlacklistIPs {
		if strings.Contains(ip, "/") {
			_, network, err := net.ParseCIDR(ip)
			if err != nil {
				rl.logger.Warn("Failed to parse CIDR for blacklist", zap.String("cidr", ip), zap.Error(err))
				continue
			}
			rl.blacklistRanges = append(rl.blacklistRanges, network)
		} else {
			rl.blacklist[ip] = true
		}
	}

	for _, country := range rl.BlockCountries {
		rl.countryBlocks[strings.ToUpper(country)] = true
	}

	for _, method := range rl.AllowedMethods {
		rl.allowedMethods[strings.ToUpper(method)] = true
	}

	for _, method := range rl.DisallowedMethods {
		rl.disallowedMethods[strings.ToUpper(method)] = true
	}

	rl.blockUserAgentRE = make([]*regexp.Regexp, 0, len(rl.BlockUserAgents))
	for _, uaPattern := range rl.BlockUserAgents {
		re, err := regexp.Compile(uaPattern)
		if err != nil {
			rl.logger.Warn("Failed to compile user agent pattern", zap.String("pattern", uaPattern), zap.Error(err))
			continue
		}
		rl.blockUserAgentRE = append(rl.blockUserAgentRE, re)
	}

	rl.blockRefererRE = make([]*regexp.Regexp, 0, len(rl.BlockReferers))
	for _, refPattern := range rl.BlockReferers {
		re, err := regexp.Compile(refPattern)
		if err != nil {
			rl.logger.Warn("Failed to compile referer pattern", zap.String("pattern", refPattern), zap.Error(err))
			continue
		}
		rl.blockRefererRE = append(rl.blockRefererRE, re)
	}

	// Инициализация правил для путей
	if rl.RulesPerPath != nil {
		for path, rule := range rl.RulesPerPath {
			if rule.RequestsPerSecond <= 0 {
				rule.RequestsPerSecond = rl.RequestsPerSecond
			}

			if rule.BlockDuration == "" {
				rule.BlockDuration = rl.BlockDuration
			}

			if rule.BurstCapacity <= 0 {
				rule.BurstCapacity = rule.RequestsPerSecond * 2
			}

			rule.whitelist = make(map[string]bool)
			for _, ip := range rule.WhitelistIPs {
				rule.whitelist[ip] = true
			}

			rule.allowedMethods = make(map[string]bool)
			for _, method := range rule.AllowedMethods {
				rule.allowedMethods[strings.ToUpper(method)] = true
			}

			rule.disallowedMethods = make(map[string]bool)
			for _, method := range rule.DisallowedMethods {
				rule.disallowedMethods[strings.ToUpper(method)] = true
			}

			var err error
			rule.blockDuration, err = time.ParseDuration(rule.BlockDuration)
			if err != nil {
				rl.logger.Warn("Failed to parse block duration for path", zap.String("path", path), zap.Error(err))
				rule.blockDuration, _ = time.ParseDuration(rl.BlockDuration)
			}
		}
	}

	var err error
	rl.blockDuration, err = time.ParseDuration(rl.BlockDuration)
	if err != nil {
		return err
	}

	rl.banDuration, err = time.ParseDuration(rl.BanDuration)
	if err != nil {
		rl.logger.Warn("Failed to parse ban duration", zap.Error(err))
		rl.banDuration, _ = time.ParseDuration("24h")
	}

	go rl.collectStats()

	// Запускаем HTTP сервер для метрик, если включено
	if rl.ExportMetrics {
		go rl.startMetricsServer()
	}

	return nil
}

func (rl *RateLimit) collectStats() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		timeKey := now.Format("15:04")

		rl.stats.Lock()
		if len(rl.stats.requestsPerInterval) >= 60 {
			rl.stats.requestsPerInterval = make(map[string]int64)
			rl.stats.blocksPerInterval = make(map[string]int64)
		}
		rl.stats.requestsPerInterval[timeKey] = 0
		rl.stats.blocksPerInterval[timeKey] = 0
		rl.stats.Unlock()
	}
}

func (rl *RateLimit) updateTopVisitors() {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	topVisitors := make(map[string]int64)

	for ip, v := range rl.visitors {
		topVisitors[ip] = int64(v.count)
	}

	if len(topVisitors) > 10 {
		type ipCount struct {
			IP    string
			Count int64
		}
		pairs := make([]ipCount, 0, len(topVisitors))
		for ip, count := range topVisitors {
			pairs = append(pairs, ipCount{IP: ip, Count: count})
		}

		sort.Slice(pairs, func(i, j int) bool {
			return pairs[i].Count > pairs[j].Count
		})

		topVisitors = make(map[string]int64)
		for i := 0; i < 10 && i < len(pairs); i++ {
			topVisitors[pairs[i].IP] = pairs[i].Count
		}
	}

	rl.stats.topVisitors = topVisitors
}

func (rl *RateLimit) Cleanup() error {
	// Выполнение очистки ресурсов плагина
	return nil
}

func (rl *RateLimit) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip, err := rl.getClientIP(r)
	if err != nil {
		rl.logger.Error("failed to get client IP", zap.Error(err))
		return next.ServeHTTP(w, r)
	}

	rl.stats.Lock()
	rl.stats.totalRequests++

	// Обновляем статистику по методу запроса
	method := r.Method
	rl.stats.methodRequests[method]++

	// Обновляем статистику по пути
	path := r.URL.Path
	rl.stats.pathHits[path]++

	timeKey := time.Now().Format("15:04")
	rl.stats.requestsPerInterval[timeKey]++
	rl.stats.Unlock()

	// Проверка белого списка IP
	if rl.isWhitelisted(ip) {
		rl.stats.Lock()
		rl.stats.totalWhitelisted++
		rl.stats.Unlock()

		return next.ServeHTTP(w, r)
	}

	// Проверка черного списка IP
	if rl.isBlacklisted(ip) {
		rl.stats.Lock()
		rl.stats.totalBlacklisted++
		rl.stats.blockReasons["Blacklisted IP"]++
		rl.stats.Unlock()

		return rl.serveBlockPage(w, r, ip, "Ваш IP адрес в черном списке")
	}

	userAgent := r.UserAgent()
	referer := r.Referer()

	// Проверка блокировки по User-Agent
	for _, re := range rl.blockUserAgentRE {
		if re.MatchString(userAgent) {
			rl.stats.Lock()
			rl.stats.totalUABlocked++
			rl.stats.blockReasons["Blocked User-Agent"]++
			rl.stats.Unlock()

			return rl.serveBlockPage(w, r, ip, "Заблокированный User-Agent")
		}
	}

	// Проверка блокировки по Referer
	for _, re := range rl.blockRefererRE {
		if referer != "" && re.MatchString(referer) {
			rl.stats.Lock()
			rl.stats.totalRefererBlocked++
			rl.stats.blockReasons["Blocked Referer"]++
			rl.stats.Unlock()

			return rl.serveBlockPage(w, r, ip, "Заблокированный источник запроса")
		}
	}

	// Проверка на скан-боты
	if rl.BlockScanBots && rl.isScanBot(r) {
		rl.stats.Lock()
		rl.stats.totalBotBlocked++
		rl.stats.blockReasons["Scan Bot"]++
		rl.stats.Unlock()

		return rl.serveBlockPage(w, r, ip, "Сканирующий бот")
	}

	// Проверка по стране
	if len(rl.countryBlocks) > 0 {
		country := rl.getCountryFromIP(ip)
		if country != "" && rl.countryBlocks[country] {
			rl.stats.Lock()
			rl.stats.totalGeoBlocked++
			rl.stats.blockReasons["Geo-blocked"]++
			rl.stats.Unlock()

			return rl.serveBlockPage(w, r, ip, "Доступ из вашей страны запрещен")
		}
	}

	// Проверка метода HTTP
	if len(rl.allowedMethods) > 0 {
		if !rl.allowedMethods[r.Method] {
			rl.stats.Lock()
			rl.stats.totalMethodBlocked++
			rl.stats.blockReasons["Method not allowed"]++
			rl.stats.Unlock()

			return rl.serveBlockPage(w, r, ip, "Метод HTTP не разрешен")
		}
	}

	if len(rl.disallowedMethods) > 0 {
		if rl.disallowedMethods[r.Method] {
			rl.stats.Lock()
			rl.stats.totalMethodBlocked++
			rl.stats.blockReasons["Method disallowed"]++
			rl.stats.Unlock()

			return rl.serveBlockPage(w, r, ip, "Метод HTTP запрещен")
		}
	}

	// Проверка JS вызова, если включена защита
	if rl.EnableJSChallenge {
		// Проверяем, есть ли токен вызова в запросе
		challengeToken := r.URL.Query().Get("xrl_challenge")
		if challengeToken != "" {
			// Проверяем валидность токена
			valid := rl.validateJSChallenge(ip, challengeToken)
			if !valid {
				rl.stats.Lock()
				rl.stats.totalJSFailed++
				rl.stats.Unlock()

				return rl.serveBlockPage(w, r, ip, "Неверное решение JS-вызова")
			}

			// Токен валиден, разрешаем запрос без проверки лимитов
			return next.ServeHTTP(w, r)
		}
	}

	// Проверка специфичных правил для пути
	if rl.RulesPerPath != nil {
		for urlPattern, rule := range rl.RulesPerPath {
			matched, err := filepath.Match(urlPattern, r.URL.Path)
			if err != nil {
				continue
			}

			if matched {
				// Проверка белого списка для пути
				if rule.whitelist[ip] {
					return next.ServeHTTP(w, r)
				}

				// Проверка разрешенных методов для пути
				if len(rule.allowedMethods) > 0 && !rule.allowedMethods[r.Method] {
					rl.stats.Lock()
					rl.stats.totalMethodBlocked++
					rl.stats.blockReasons["Path method not allowed"]++
					rl.stats.Unlock()

					return rl.serveBlockPage(w, r, ip, "Метод HTTP не разрешен для данного пути")
				}

				// Проверка запрещенных методов для пути
				if len(rule.disallowedMethods) > 0 && rule.disallowedMethods[r.Method] {
					rl.stats.Lock()
					rl.stats.totalMethodBlocked++
					rl.stats.blockReasons["Path method disallowed"]++
					rl.stats.Unlock()

					return rl.serveBlockPage(w, r, ip, "Метод HTTP запрещен для данного пути")
				}

				// Проверка превышения лимитов для пути
				if rl.limitExceededForPath(ip, userAgent, rule) {
					rl.stats.Lock()
					rl.stats.totalPathBlocked++
					rl.stats.blockReasons["Path rate limit exceeded"]++
					rl.stats.Unlock()

					return rl.serveBlockPage(w, r, ip, "Превышение лимита запросов для данного пути")
				}

				// Путь проверен и прошел все проверки - продолжаем обработку
				break
			}
		}
	}

	// Проверка стандартной блокировки
	if rl.isBlocked(ip) {
		rl.stats.Lock()
		rl.stats.totalBlocked++
		rl.stats.blocksPerInterval[timeKey]++
		rl.stats.Unlock()

		reason := "Превышение лимита запросов"
		rl.mu.RLock()
		if v, ok := rl.visitors[ip]; ok && v.blockReason != "" {
			reason = v.blockReason
		}
		rl.mu.RUnlock()

		// Если включены JS вызовы, проверяем, нужно ли их выдать
		if rl.EnableJSChallenge && rl.shouldIssueJSChallenge(ip) {
			rl.stats.Lock()
			rl.stats.totalJSChallenges++
			rl.stats.Unlock()

			return rl.serveJSChallenge(w, r, ip)
		}

		return rl.serveBlockPage(w, r, ip, reason)
	}

	// Проверка превышения стандартного лимита
	if rl.limitExceeded(ip, userAgent) {
		rl.stats.Lock()
		rl.stats.totalBlocked++
		rl.stats.blocksPerInterval[timeKey]++
		rl.stats.blockReasons["Rate limit exceeded"]++
		rl.stats.Unlock()

		// Если включены JS вызовы, проверяем, нужно ли их выдать
		if rl.EnableJSChallenge && rl.shouldIssueJSChallenge(ip) {
			rl.stats.Lock()
			rl.stats.totalJSChallenges++
			rl.stats.Unlock()

			return rl.serveJSChallenge(w, r, ip)
		}

		return rl.serveBlockPage(w, r, ip, "Превышение лимита запросов")
	}

	// Обновляем последние данные посетителя
	rl.mu.Lock()
	if v, exists := rl.visitors[ip]; exists {
		// Сохраняем информацию о последних запросах
		v.lastPaths = append(v.lastPaths, r.URL.Path)
		if len(v.lastPaths) > 10 {
			v.lastPaths = v.lastPaths[len(v.lastPaths)-10:]
		}

		v.lastMethods = append(v.lastMethods, r.Method)
		if len(v.lastMethods) > 10 {
			v.lastMethods = v.lastMethods[len(v.lastMethods)-10:]
		}

		if referer != "" {
			v.referers = append(v.referers, referer)
			if len(v.referers) > 10 {
				v.referers = v.referers[len(v.referers)-10:]
			}
		}
	}
	rl.mu.Unlock()

	return next.ServeHTTP(w, r)
}

func (rl *RateLimit) getClientIP(r *http.Request) (string, error) {
	// Если включена опция TrustForwardedFor, используем заголовок X-Forwarded-For
	if rl.TrustForwardedFor {
		forwardedFor := r.Header.Get("X-Forwarded-For")
		if forwardedFor != "" {
			ips := strings.Split(forwardedFor, ",")
			return strings.TrimSpace(ips[0]), nil
		}
	}

	// Иначе используем стандартные способы определения IP
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP, nil
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr, nil
	}
	return host, nil
}

func (rl *RateLimit) isBlocked(ip string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	v, exists := rl.visitors[ip]
	if !exists {
		return false
	}

	if !v.blocked {
		return false
	}

	if time.Now().After(v.unblockAt) {
		v.blocked = false
		return false
	}

	return true
}

func (rl *RateLimit) limitExceeded(ip, userAgent string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, exists := rl.visitors[ip]

	if !exists {
		rl.visitors[ip] = &visitor{
			count:      1,
			lastSeen:   now,
			blocked:    false,
			requestIPs: []string{ip},
			userAgent:  userAgent,
		}
		return false
	}

	if now.Sub(v.lastSeen) > time.Second {
		v.count = 0
		v.lastSeen = now
	}

	v.count++
	v.lastSeen = now
	v.userAgent = userAgent

	if v.count > rl.RequestsPerSecond {
		v.blocked = true
		v.blockedAt = now
		v.unblockAt = now.Add(rl.blockDuration)
		v.blockReason = "Превышение лимита запросов"
		return true
	}

	return false
}

func (rl *RateLimit) isScanBot(r *http.Request) bool {
	userAgent := strings.ToLower(r.UserAgent())

	// Список паттернов сканирующих ботов
	scanBotPatterns := []string{
		"nmap", "nikto", "sqlmap", "zgrab", "masscan", "dirbuster", "dirb",
		"wpscan", "jorgee", "gobuster", "hydra", "nessus", "openvas",
		"burpsuite", "acunetix", "qualys", "nuclei", "zap", "arachni",
	}

	for _, pattern := range scanBotPatterns {
		if strings.Contains(userAgent, pattern) {
			return true
		}
	}

	// Проверка подозрительных заголовков
	suspiciousHeaders := []string{
		"X-Scan-By", "X-Scan", "X-Scanner",
		"X-Vulnerability-Scanner", "X-Security-Scanner",
	}

	for _, header := range suspiciousHeaders {
		if r.Header.Get(header) != "" {
			return true
		}
	}

	// Проверка подозрительных путей запросов (попытки получить доступ к админке, бэкапам, etc)
	suspiciousPaths := []string{
		"wp-admin", "admin", "administrator", "login", "wp-login",
		"phpmyadmin", "mysql", "config", "bak", "backup", "sql", "old",
		".git", ".svn", ".env", ".htaccess", ".htpasswd",
		"setup", "install", "passwd", "password",
	}

	path := strings.ToLower(r.URL.Path)
	for _, susPath := range suspiciousPaths {
		if strings.Contains(path, susPath) {
			// Дополнительная проверка - может быть это просто легитимный запрос
			referer := r.Header.Get("Referer")
			// Если нет реферера при доступе к админке - подозрительно
			if referer == "" {
				return true
			}
		}
	}

	return false
}

func (rl *RateLimit) getCountryFromIP(ip string) string {
	// В реальном приложении здесь должна быть проверка IP через базу GeoIP
	// Для демонстрации просто заглушка - предполагаем, что все китайские IP начинаются с 1.1.
	if strings.HasPrefix(ip, "1.1.") {
		return "CN"
	}

	// Для российских IP
	if strings.HasPrefix(ip, "95.") || strings.HasPrefix(ip, "77.") {
		return "RU"
	}

	return ""
}

func (rl *RateLimit) serveBlockPage(w http.ResponseWriter, r *http.Request, ip, reason string) error {
	rl.mu.RLock()
	v, exists := rl.visitors[ip]
	rl.mu.RUnlock()

	if !exists {
		// Если посетитель не существует, создаем временного для отображения блокировки
		v = &visitor{
			blockedAt: time.Now(),
			unblockAt: time.Now().Add(rl.blockDuration),
			blocked:   true,
		}
	}

	now := time.Now()
	remainingTime := v.unblockAt.Sub(now)
	minutes := int(remainingTime.Minutes())
	seconds := int(remainingTime.Seconds()) % 60

	templateData := map[string]interface{}{
		"IP":             ip,
		"RequestLimit":   rl.RequestsPerSecond,
		"BlockDuration":  int(rl.blockDuration.Minutes()),
		"RemainingMin":   minutes,
		"RemainingSec":   seconds,
		"BlockReason":    reason,
		"TotalRemaining": fmt.Sprintf("%02d:%02d", minutes, seconds),
		"UserAgent":      r.UserAgent(),
	}

	tmpl, err := template.ParseFiles(filepath.Join("xratelimit", "templates", "block.html"))
	if err != nil {
		tmpl, err = template.New("block").Parse(defaultBlockTemplate)
		if err != nil {
			return err
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateData); err != nil {
		return err
	}

	_, err = w.Write(buf.Bytes())
	return err
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var rl RateLimit

	// Инициализация структур данных
	rl.RulesPerPath = make(map[string]*PathRule)

	for h.Next() {
		args := h.RemainingArgs()
		switch len(args) {
		case 1:
			rps, err := strconv.Atoi(args[0])
			if err != nil {
				return nil, h.ArgErr()
			}
			rl.RequestsPerSecond = rps
		case 2:
			rps, err := strconv.Atoi(args[0])
			if err != nil {
				return nil, h.ArgErr()
			}
			rl.RequestsPerSecond = rps
			rl.BlockDuration = args[1]
		case 0:
			// Используем значения по умолчанию
		default:
			return nil, h.ArgErr()
		}

		for h.NextBlock(0) {
			switch h.Val() {
			case "whitelist":
				whitelistArgs := h.RemainingArgs()
				if len(whitelistArgs) == 0 {
					return nil, h.ArgErr()
				}
				rl.WhitelistIPs = append(rl.WhitelistIPs, whitelistArgs...)

			case "blacklist":
				blacklistArgs := h.RemainingArgs()
				if len(blacklistArgs) == 0 {
					return nil, h.ArgErr()
				}
				rl.BlacklistIPs = append(rl.BlacklistIPs, blacklistArgs...)

			case "block_user_agents":
				uaArgs := h.RemainingArgs()
				if len(uaArgs) == 0 {
					return nil, h.ArgErr()
				}
				rl.BlockUserAgents = append(rl.BlockUserAgents, uaArgs...)

			case "block_referers":
				refArgs := h.RemainingArgs()
				if len(refArgs) == 0 {
					return nil, h.ArgErr()
				}
				rl.BlockReferers = append(rl.BlockReferers, refArgs...)

			case "block_countries":
				countryArgs := h.RemainingArgs()
				if len(countryArgs) == 0 {
					return nil, h.ArgErr()
				}
				rl.BlockCountries = append(rl.BlockCountries, countryArgs...)

			case "block_scan_bots":
				rl.BlockScanBots = true

			case "allowed_methods":
				methodArgs := h.RemainingArgs()
				if len(methodArgs) == 0 {
					return nil, h.ArgErr()
				}
				rl.AllowedMethods = append(rl.AllowedMethods, methodArgs...)

			case "disallowed_methods":
				methodArgs := h.RemainingArgs()
				if len(methodArgs) == 0 {
					return nil, h.ArgErr()
				}
				rl.DisallowedMethods = append(rl.DisallowedMethods, methodArgs...)

			case "block_duration":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				rl.BlockDuration = h.Val()

			case "burst_capacity":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				burstCap, err := strconv.Atoi(h.Val())
				if err != nil {
					return nil, h.ArgErr()
				}
				rl.BurstCapacity = burstCap

			case "enable_js_challenge":
				rl.EnableJSChallenge = true

			case "ip_hashing_key":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				rl.IPHashingKey = h.Val()

			case "ban_after_blocks":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				banAfter, err := strconv.Atoi(h.Val())
				if err != nil {
					return nil, h.ArgErr()
				}
				rl.BanAfterBlocks = banAfter

			case "ban_duration":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				rl.BanDuration = h.Val()

			case "custom_response_code":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				code, err := strconv.Atoi(h.Val())
				if err != nil {
					return nil, h.ArgErr()
				}
				rl.CustomResponseCode = code

			case "export_metrics":
				rl.ExportMetrics = true

			case "metrics_path":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				rl.MetricsPath = h.Val()

			case "log_level":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				rl.LogLevel = h.Val()

			case "trust_forwarded_for":
				rl.TrustForwardedFor = true

			case "path_rule":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				path := h.Val()

				// Создаем правило для пути
				rule := &PathRule{
					Path: path,
				}

				// Парсим блок настроек для пути
				for h.NextBlock(1) {
					switch h.Val() {
					case "requests_per_second":
						if !h.NextArg() {
							return nil, h.ArgErr()
						}
						rps, err := strconv.Atoi(h.Val())
						if err != nil {
							return nil, h.ArgErr()
						}
						rule.RequestsPerSecond = rps

					case "block_duration":
						if !h.NextArg() {
							return nil, h.ArgErr()
						}
						rule.BlockDuration = h.Val()

					case "whitelist":
						whitelistArgs := h.RemainingArgs()
						if len(whitelistArgs) == 0 {
							return nil, h.ArgErr()
						}
						rule.WhitelistIPs = append(rule.WhitelistIPs, whitelistArgs...)

					case "allowed_methods":
						methodArgs := h.RemainingArgs()
						if len(methodArgs) == 0 {
							return nil, h.ArgErr()
						}
						rule.AllowedMethods = append(rule.AllowedMethods, methodArgs...)

					case "disallowed_methods":
						methodArgs := h.RemainingArgs()
						if len(methodArgs) == 0 {
							return nil, h.ArgErr()
						}
						rule.DisallowedMethods = append(rule.DisallowedMethods, methodArgs...)

					case "burst_capacity":
						if !h.NextArg() {
							return nil, h.ArgErr()
						}
						burstCap, err := strconv.Atoi(h.Val())
						if err != nil {
							return nil, h.ArgErr()
						}
						rule.BurstCapacity = burstCap

					default:
						return nil, h.Errf("unknown path rule directive %s", h.Val())
					}
				}

				// Добавляем правило в карту
				rl.RulesPerPath[path] = rule

			default:
				return nil, h.Errf("unknown subdirective %s", h.Val())
			}
		}
	}

	return &rl, nil
}

const defaultBlockTemplate = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP адрес заблокирован</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background-color: #121212;
            background-image: radial-gradient(circle at top right, #1f1f1f 0%, #121212 70%);
            color: white;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            overflow: hidden;
        }
        .container {
            max-width: 650px;
            width: 90%;
            padding: 40px;
            border: 1px solid #333;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), 0 0 20px rgba(242, 75, 75, 0.2);
            text-align: center;
            position: relative;
            background-color: rgba(30, 30, 30, 0.95);
            overflow: hidden;
            animation: pulse 3s infinite alternate;
        }
        @keyframes pulse {
            0% {
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), 0 0 20px rgba(242, 75, 75, 0.2);
            }
            100% {
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), 0 0 40px rgba(242, 75, 75, 0.4);
            }
        }
        .container::before {
            content: '';
            position: absolute;
            top: -10px;
            left: -10px;
            right: -10px;
            height: 5px;
            background: linear-gradient(90deg, #f24b4b, #f24b4b33, #f24b4b);
            z-index: 1;
            animation: slide 4s linear infinite;
        }
        @keyframes slide {
            0% {
                transform: translateX(-100%);
            }
            100% {
                transform: translateX(100%);
            }
        }
        h1 {
            color: #f24b4b;
            margin-bottom: 30px;
            font-size: 2.2rem;
            text-shadow: 0 0 10px rgba(242, 75, 75, 0.3);
        }
        p {
            margin-bottom: 20px;
            line-height: 1.7;
            font-size: 1.1rem;
            color: #e0e0e0;
        }
        .octagon {
            width: 80px;
            height: 80px;
            background-color: #f24b4b;
            position: relative;
            margin: 0 auto 30px;
            clip-path: polygon(30% 0%, 70% 0%, 100% 30%, 100% 70%, 70% 100%, 30% 100%, 0% 70%, 0% 30%);
            box-shadow: 0 0 20px rgba(242, 75, 75, 0.5);
            animation: rotate 8s linear infinite;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        @keyframes rotate {
            0% {
                transform: rotate(0deg);
            }
            100% {
                transform: rotate(360deg);
            }
        }
        .octagon::before {
            content: '⚠';
            font-size: 40px;
            color: white;
            display: block;
            text-align: center;
            animation: counter-rotate 8s linear infinite;
        }
        @keyframes counter-rotate {
            0% {
                transform: rotate(0deg);
            }
            100% {
                transform: rotate(-360deg);
            }
        }
        .details {
            background-color: rgba(40, 40, 40, 0.7);
            border-radius: 8px;
            padding: 20px;
            margin: 30px 0;
            text-align: left;
            border-left: 3px solid #f24b4b;
        }
        .detail-item {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .detail-item:last-child {
            border-bottom: none;
        }
        .detail-label {
            color: #aaa;
            font-weight: 500;
        }
        .detail-value {
            color: #fff;
            font-weight: 600;
        }
        .countdown {
            font-size: 2.4rem;
            color: #f24b4b;
            font-weight: bold;
            margin: 20px 0;
            text-shadow: 0 0 10px rgba(242, 75, 75, 0.3);
        }
        .countdown-container {
            margin-top: 30px;
            padding: 20px;
            background-color: rgba(242, 75, 75, 0.1);
            border-radius: 8px;
        }
        .countdown-container h2 {
            color: #f24b4b;
            font-size: 1.4rem;
            margin-bottom: 10px;
        }
        footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            border-top: 1px solid #333;
            color: #888;
            position: relative;
        }
        footer p {
            margin: 0;
            font-size: 0.9rem;
        }
        footer a {
            position: relative;
            display: inline-block;
            color: #f24b4b !important;
            text-decoration: none;
            transition: all 0.3s;
        }
        footer a:hover {
            text-shadow: 0 0 8px rgba(242, 75, 75, 0.5);
        }
        footer a::after {
            content: '';
            position: absolute;
            width: 100%;
            height: 1px;
            bottom: -2px;
            left: 0;
            background-color: #f24b4b;
            transform: scaleX(0);
            transform-origin: bottom right;
            transition: transform 0.3s;
        }
        footer a:hover::after {
            transform: scaleX(1);
            transform-origin: bottom left;
        }
        @media (max-width: 600px) {
            .container {
                padding: 25px;
                width: 95%;
            }
            h1 {
                font-size: 1.8rem;
            }
            .countdown {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="octagon"></div>
        <h1>Ваш IP адрес заблокирован</h1>
        <p>
            Наша система обнаружила подозрительную активность с вашего IP-адреса. В целях безопасности мы временно ограничили доступ к сайту.
        </p>
        
        <div class="details">
            <div class="detail-item">
                <span class="detail-label">IP адрес:</span>
                <span class="detail-value">{{.IP}}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Причина блокировки:</span>
                <span class="detail-value">{{.BlockReason}}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Лимит запросов:</span>
                <span class="detail-value">{{.RequestLimit}} в секунду</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Время блокировки:</span>
                <span class="detail-value">{{.BlockDuration}} минут</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">User-Agent:</span>
                <span class="detail-value" style="font-size: 0.85em; word-break: break-all;">{{.UserAgent}}</span>
            </div>
        </div>
        
        <div class="countdown-container">
            <h2>Блокировка будет снята через:</h2>
            <div class="countdown">
                <span id="timer">{{.TotalRemaining}}</span>
            </div>
        </div>
        
        <p>После окончания блокировки вы сможете продолжить использование сайта без ограничений.</p>
        
        <footer>
            <p>Под защитой <strong>c0re</strong> | <a href="https://c0rex86.ru" target="_blank">c0rex86.ru</a></p>
        </footer>
    </div>

    <script>
        let countdownDate = new Date();
        countdownDate.setMinutes(countdownDate.getMinutes() + parseInt("{{.RemainingMin}}"));
        countdownDate.setSeconds(countdownDate.getSeconds() + parseInt("{{.RemainingSec}}"));
        
        let timer = document.getElementById('timer');
        
        let countdown = setInterval(function() {
            let now = new Date().getTime();
            let distance = countdownDate - now;
            
            let minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
            let seconds = Math.floor((distance % (1000 * 60)) / 1000);
            
            timer.innerHTML = minutes.toString().padStart(2, '0') + ":" + seconds.toString().padStart(2, '0');
            
            if (distance < 0) {
                clearInterval(countdown);
                timer.innerHTML = "00:00";
                window.location.reload();
            }
        }, 1000);
    </script>
</body>
</html>`

func (rl *RateLimit) startMetricsServer() {
	mux := http.NewServeMux()
	mux.HandleFunc(rl.MetricsPath, func(w http.ResponseWriter, r *http.Request) {
		rl.stats.RLock()
		defer rl.stats.RUnlock()

		// Формируем метрики в формате Prometheus
		metrics := []string{
			fmt.Sprintf("# HELP xratelimit_total_requests Total number of requests\n"),
			fmt.Sprintf("# TYPE xratelimit_total_requests counter\n"),
			fmt.Sprintf("xratelimit_total_requests %d\n", rl.stats.totalRequests),

			fmt.Sprintf("# HELP xratelimit_total_blocked Total number of blocked requests\n"),
			fmt.Sprintf("# TYPE xratelimit_total_blocked counter\n"),
			fmt.Sprintf("xratelimit_total_blocked %d\n", rl.stats.totalBlocked),

			fmt.Sprintf("# HELP xratelimit_total_whitelisted Total number of whitelisted requests\n"),
			fmt.Sprintf("# TYPE xratelimit_total_whitelisted counter\n"),
			fmt.Sprintf("xratelimit_total_whitelisted %d\n", rl.stats.totalWhitelisted),

			fmt.Sprintf("# HELP xratelimit_total_blacklisted Total number of blacklisted requests\n"),
			fmt.Sprintf("# TYPE xratelimit_total_blacklisted counter\n"),
			fmt.Sprintf("xratelimit_total_blacklisted %d\n", rl.stats.totalBlacklisted),

			fmt.Sprintf("# HELP xratelimit_total_bot_blocked Total number of bot-blocked requests\n"),
			fmt.Sprintf("# TYPE xratelimit_total_bot_blocked counter\n"),
			fmt.Sprintf("xratelimit_total_bot_blocked %d\n", rl.stats.totalBotBlocked),

			fmt.Sprintf("# HELP xratelimit_total_ua_blocked Total number of user-agent blocked requests\n"),
			fmt.Sprintf("# TYPE xratelimit_total_ua_blocked counter\n"),
			fmt.Sprintf("xratelimit_total_ua_blocked %d\n", rl.stats.totalUABlocked),

			fmt.Sprintf("# HELP xratelimit_total_geo_blocked Total number of geo-blocked requests\n"),
			fmt.Sprintf("# TYPE xratelimit_total_geo_blocked counter\n"),
			fmt.Sprintf("xratelimit_total_geo_blocked %d\n", rl.stats.totalGeoBlocked),

			fmt.Sprintf("# HELP xratelimit_total_referer_blocked Total number of referer-blocked requests\n"),
			fmt.Sprintf("# TYPE xratelimit_total_referer_blocked counter\n"),
			fmt.Sprintf("xratelimit_total_referer_blocked %d\n", rl.stats.totalRefererBlocked),

			fmt.Sprintf("# HELP xratelimit_total_method_blocked Total number of method-blocked requests\n"),
			fmt.Sprintf("# TYPE xratelimit_total_method_blocked counter\n"),
			fmt.Sprintf("xratelimit_total_method_blocked %d\n", rl.stats.totalMethodBlocked),

			fmt.Sprintf("# HELP xratelimit_total_path_blocked Total number of path-blocked requests\n"),
			fmt.Sprintf("# TYPE xratelimit_total_path_blocked counter\n"),
			fmt.Sprintf("xratelimit_total_path_blocked %d\n", rl.stats.totalPathBlocked),

			fmt.Sprintf("# HELP xratelimit_total_js_challenges Total number of JavaScript challenges issued\n"),
			fmt.Sprintf("# TYPE xratelimit_total_js_challenges counter\n"),
			fmt.Sprintf("xratelimit_total_js_challenges %d\n", rl.stats.totalJSChallenges),

			fmt.Sprintf("# HELP xratelimit_total_js_failed Total number of failed JavaScript challenges\n"),
			fmt.Sprintf("# TYPE xratelimit_total_js_failed counter\n"),
			fmt.Sprintf("xratelimit_total_js_failed %d\n", rl.stats.totalJSFailed),
		}

		// Добавляем метрики по методам HTTP
		for method, count := range rl.stats.methodRequests {
			metrics = append(metrics,
				fmt.Sprintf("# HELP xratelimit_method_requests Total requests by HTTP method\n"),
				fmt.Sprintf("# TYPE xratelimit_method_requests counter\n"),
				fmt.Sprintf("xratelimit_method_requests{method=\"%s\"} %d\n", method, count),
			)
		}

		// Добавляем метрики по путям
		for path, count := range rl.stats.pathHits {
			cleanPath := strings.ReplaceAll(path, "\"", "\\\"")
			metrics = append(metrics,
				fmt.Sprintf("# HELP xratelimit_path_hits Total hits by path\n"),
				fmt.Sprintf("# TYPE xratelimit_path_hits counter\n"),
				fmt.Sprintf("xratelimit_path_hits{path=\"%s\"} %d\n", cleanPath, count),
			)
		}

		// Пишем метрики в ответ
		w.Header().Set("Content-Type", "text/plain")
		for _, metric := range metrics {
			w.Write([]byte(metric))
		}
	})

	// Запускаем сервер на порту 9001
	server := &http.Server{
		Addr:    ":9001",
		Handler: mux,
	}

	rl.logger.Info("Starting metrics server on port 9001")
	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		rl.logger.Error("Metrics server error", zap.Error(err))
	}
}

func (rl *RateLimit) isWhitelisted(ip string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	// Проверка прямого совпадения
	if rl.whitelist[ip] {
		return true
	}

	// Проверка по диапазонам IP
	if len(rl.whitelistRanges) > 0 {
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			for _, ipNet := range rl.whitelistRanges {
				if ipNet.Contains(parsedIP) {
					return true
				}
			}
		}
	}

	return false
}

func (rl *RateLimit) isBlacklisted(ip string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	// Проверка прямого совпадения
	if rl.blacklist[ip] {
		return true
	}

	// Проверка по диапазонам IP
	if len(rl.blacklistRanges) > 0 {
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			for _, ipNet := range rl.blacklistRanges {
				if ipNet.Contains(parsedIP) {
					return true
				}
			}
		}
	}

	return false
}

func (rl *RateLimit) limitExceededForPath(ip, userAgent string, rule *PathRule) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, exists := rl.visitors[ip]

	if !exists {
		rl.visitors[ip] = &visitor{
			count:       1,
			lastSeen:    now,
			blocked:     false,
			requestIPs:  []string{ip},
			userAgent:   userAgent,
			burstTokens: rule.BurstCapacity,
			challenges:  make(map[string]time.Time),
		}
		return false
	}

	// Проверка на разрешение всплесков трафика (burst capacity)
	if v.burstTokens > 0 {
		v.burstTokens--
		return false
	}

	if now.Sub(v.lastSeen) > time.Second {
		v.count = 0
		v.lastSeen = now
		v.burstTokens = rule.BurstCapacity
		return false
	}

	v.count++
	v.lastSeen = now
	v.userAgent = userAgent

	if v.count > rule.RequestsPerSecond {
		v.blocked = true
		v.blockedAt = now
		v.unblockAt = now.Add(rule.blockDuration)
		v.blockReason = "Превышение лимита запросов для пути"
		v.totalBlocks++
		return true
	}

	return false
}

func (rl *RateLimit) shouldIssueJSChallenge(ip string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	v, exists := rl.visitors[ip]
	if !exists {
		return false
	}

	// Если это первая или вторая блокировка, выдаем JS-вызов
	if v.totalBlocks <= 2 {
		return true
	}

	return false
}

func (rl *RateLimit) validateJSChallenge(ip, token string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	v, exists := rl.visitors[ip]
	if !exists {
		return false
	}

	// Проверка существования токена и срока его действия
	expiryTime, exists := v.challenges[token]
	if !exists {
		return false
	}

	if time.Now().After(expiryTime) {
		// Токен просрочен
		delete(v.challenges, token)
		return false
	}

	// Токен валиден, удаляем его из списка
	delete(v.challenges, token)

	// Снимаем блокировку
	v.blocked = false
	v.count = 0

	return true
}

func (rl *RateLimit) generateJSChallengeToken(ip string) string {
	// Генерируем случайный токен
	token := fmt.Sprintf("%s-%d", ip, time.Now().UnixNano())

	// Хешируем токен с солью
	hasher := sha256.New()
	hasher.Write([]byte(token))
	hasher.Write([]byte(rl.IPHashingKey))

	// Сохраняем токен и время истечения
	hashHex := hex.EncodeToString(hasher.Sum(nil))

	rl.mu.Lock()
	v, exists := rl.visitors[ip]
	if exists {
		if v.challenges == nil {
			v.challenges = make(map[string]time.Time)
		}
		// Токен действителен 5 минут
		v.challenges[hashHex] = time.Now().Add(5 * time.Minute)
	}
	rl.mu.Unlock()

	return hashHex
}

// Метод для сервирования JS-вызова
func (rl *RateLimit) serveJSChallenge(w http.ResponseWriter, r *http.Request, ip string) error {
	token := rl.generateJSChallengeToken(ip)

	// Создаем URL для редиректа после прохождения проверки
	originalURL := r.URL.String()
	challengeParam := "xrl_challenge=" + token
	redirectURL := originalURL
	if strings.Contains(originalURL, "?") {
		redirectURL += "&" + challengeParam
	} else {
		redirectURL += "?" + challengeParam
	}

	templateData := map[string]interface{}{
		"IP":             ip,
		"BlockReason":    "Превышение лимита запросов",
		"RedirectURL":    redirectURL,
		"ChallengeToken": token,
	}

	// Используем шаблон для JS-вызова
	tmpl, err := template.New("js-challenge").Parse(jsChallengeTmpl)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateData); err != nil {
		return err
	}

	_, err = w.Write(buf.Bytes())
	return err
}

// Шаблон для JS вызова
const jsChallengeTmpl = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Проверка безопасности</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background-color: #121212;
            background-image: radial-gradient(circle at top right, #1f1f1f 0%, #121212 70%);
            color: white;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            overflow: hidden;
        }
        .container {
            max-width: 650px;
            width: 90%;
            padding: 40px;
            border: 1px solid #333;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), 0 0 20px rgba(242, 75, 75, 0.2);
            text-align: center;
            position: relative;
            background-color: rgba(30, 30, 30, 0.95);
            overflow: hidden;
            animation: pulse 3s infinite alternate;
        }
        @keyframes pulse {
            0% {
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), 0 0 20px rgba(242, 75, 75, 0.2);
            }
            100% {
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), 0 0 40px rgba(242, 75, 75, 0.4);
            }
        }
        .container::before {
            content: '';
            position: absolute;
            top: -10px;
            left: -10px;
            right: -10px;
            height: 5px;
            background: linear-gradient(90deg, #f24b4b, #f24b4b33, #f24b4b);
            z-index: 1;
            animation: slide 4s linear infinite;
        }
        @keyframes slide {
            0% {
                transform: translateX(-100%);
            }
            100% {
                transform: translateX(100%);
            }
        }
        h1 {
            color: #f24b4b;
            margin-bottom: 30px;
            font-size: 2.2rem;
            text-shadow: 0 0 10px rgba(242, 75, 75, 0.3);
        }
        p {
            margin-bottom: 20px;
            line-height: 1.7;
            font-size: 1.1rem;
            color: #e0e0e0;
        }
        .spinner {
            display: inline-block;
            width: 80px;
            height: 80px;
            margin: 30px auto;
        }
        .spinner:after {
            content: " ";
            display: block;
            width: 64px;
            height: 64px;
            margin: 8px;
            border-radius: 50%;
            border: 6px solid #f24b4b;
            border-color: #f24b4b transparent #f24b4b transparent;
            animation: spin 1.2s linear infinite;
        }
        @keyframes spin {
            0% {
                transform: rotate(0deg);
            }
            100% {
                transform: rotate(360deg);
            }
        }
        .progress {
            height: 4px;
            width: 100%;
            background-color: #333;
            border-radius: 2px;
            margin: 30px 0;
            overflow: hidden;
        }
        .progress-bar {
            height: 100%;
            width: 0%;
            background-color: #f24b4b;
            transition: width 0.5s;
        }
        footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            border-top: 1px solid #333;
            color: #888;
            position: relative;
        }
        footer p {
            margin: 0;
            font-size: 0.9rem;
        }
        footer a {
            position: relative;
            display: inline-block;
            color: #f24b4b !important;
            text-decoration: none;
            transition: all 0.3s;
        }
        footer a:hover {
            text-shadow: 0 0 8px rgba(242, 75, 75, 0.5);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Проверка безопасности</h1>
        <p>Система обнаружила подозрительную активность с вашего IP-адреса. Мы проводим проверку, чтобы убедиться, что вы не бот.</p>
        
        <div class="progress">
            <div class="progress-bar" id="progress-bar"></div>
        </div>
        
        <div class="spinner" id="spinner"></div>
        
        <p id="status-text">Выполняем проверку...</p>
        
        <footer>
            <p>Под защитой <strong>c0re</strong> | <a href="https://c0rex86.ru" target="_blank">c0rex86.ru</a></p>
        </footer>
    </div>
    
    <script>
        // Функция проверки
        function performCheck() {
            const progressBar = document.getElementById('progress-bar');
            let progress = 0;
            
            // Имитация процесса проверки
            const interval = setInterval(() => {
                progress += 5;
                progressBar.style.width = progress + '%';
                
                if (progress >= 100) {
                    clearInterval(interval);
                    document.getElementById('status-text').textContent = 'Проверка завершена. Перенаправляем...';
                    setTimeout(() => {
                        window.location.href = "{{.RedirectURL}}";
                    }, 1000);
                }
            }, 150);
            
            // Выполняем некоторую "работу", чтобы показать, что это реальный клиент
            for (let i = 0; i < 1000000; i++) {
                Math.sqrt(Math.random() * 10000);
            }
        }
        
        // Запускаем проверку после загрузки страницы
        window.onload = performCheck;
    </script>
</body>
</html>`
