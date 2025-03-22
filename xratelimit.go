package xratelimit

import (
	"bytes"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"path/filepath"
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
	AdminPort         int      `json:"admin_port,omitempty"`
	WhitelistIPs      []string `json:"whitelist_ips,omitempty"`
	BlacklistIPs      []string `json:"blacklist_ips,omitempty"`

	blockDuration time.Duration
	logger        *zap.Logger
	visitors      map[string]*visitor
	whitelist     map[string]bool
	blacklist     map[string]bool
	mu            sync.RWMutex
	adminServer   *adminServer

	stats struct {
		sync.RWMutex
		totalRequests       int64
		totalBlocked        int64
		totalWhitelisted    int64
		totalBlacklisted    int64
		requestsPerInterval map[string]int64
		blocksPerInterval   map[string]int64
		lastIntervalUpdate  time.Time
		topVisitors         map[string]int64
	}
}

type visitor struct {
	count      int
	lastSeen   time.Time
	blocked    bool
	blockedAt  time.Time
	unblockAt  time.Time
	requestIPs []string
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

	rl.stats.requestsPerInterval = make(map[string]int64)
	rl.stats.blocksPerInterval = make(map[string]int64)
	rl.stats.topVisitors = make(map[string]int64)
	rl.stats.lastIntervalUpdate = time.Now()

	if rl.RequestsPerSecond <= 0 {
		rl.RequestsPerSecond = 10
	}

	if rl.BlockDuration == "" {
		rl.BlockDuration = "5m"
	}

	if rl.AdminPort <= 0 {
		rl.AdminPort = 6666
	}

	for _, ip := range rl.WhitelistIPs {
		rl.whitelist[ip] = true
	}

	for _, ip := range rl.BlacklistIPs {
		rl.blacklist[ip] = true
	}

	var err error
	rl.blockDuration, err = time.ParseDuration(rl.BlockDuration)
	if err != nil {
		return err
	}

	rl.adminServer = newAdminServer(rl, rl.AdminPort, rl.logger)
	go rl.adminServer.start()

	go rl.collectStats()

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
	if rl.adminServer != nil {
		return rl.adminServer.stop()
	}
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

	timeKey := time.Now().Format("15:04")
	rl.stats.requestsPerInterval[timeKey]++
	rl.stats.Unlock()

	rl.mu.RLock()
	if rl.whitelist[ip] {
		rl.mu.RUnlock()

		rl.stats.Lock()
		rl.stats.totalWhitelisted++
		rl.stats.Unlock()

		return next.ServeHTTP(w, r)
	}

	if rl.blacklist[ip] {
		rl.mu.RUnlock()

		rl.stats.Lock()
		rl.stats.totalBlacklisted++
		rl.stats.Unlock()

		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access denied: Your IP is blacklisted"))
		return nil
	}
	rl.mu.RUnlock()
	if rl.isBlocked(ip) {
		rl.stats.Lock()
		rl.stats.totalBlocked++
		rl.stats.blocksPerInterval[timeKey]++
		rl.stats.Unlock()

		return rl.serveBlockPage(w, r, ip)
	}

	if rl.limitExceeded(ip) {
		rl.stats.Lock()
		rl.stats.totalBlocked++
		rl.stats.blocksPerInterval[timeKey]++
		rl.stats.Unlock()

		return rl.serveBlockPage(w, r, ip)
	}

	return next.ServeHTTP(w, r)
}

func (rl *RateLimit) getClientIP(r *http.Request) (string, error) {
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		ips := strings.Split(forwardedFor, ",")
		return strings.TrimSpace(ips[0]), nil
	}

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

func (rl *RateLimit) limitExceeded(ip string) bool {
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
		}
		return false
	}

	if now.Sub(v.lastSeen) > time.Second {
		v.count = 0
		v.lastSeen = now
	}

	v.count++
	v.lastSeen = now

	if v.count > rl.RequestsPerSecond {
		v.blocked = true
		v.blockedAt = now
		v.unblockAt = now.Add(rl.blockDuration)
		return true
	}

	return false
}

func (rl *RateLimit) serveBlockPage(w http.ResponseWriter, r *http.Request, ip string) error {
	rl.mu.RLock()
	v, exists := rl.visitors[ip]
	rl.mu.RUnlock()

	if !exists {
		return fmt.Errorf("visitor not found for IP %s", ip)
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
		"BlockReason":    "Превышение лимита запросов",
		"TotalRemaining": fmt.Sprintf("%02d:%02d", minutes, seconds),
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
		case 3:
			rps, err := strconv.Atoi(args[0])
			if err != nil {
				return nil, h.ArgErr()
			}
			rl.RequestsPerSecond = rps
			rl.BlockDuration = args[1]

			port, err := strconv.Atoi(args[2])
			if err != nil {
				return nil, h.ArgErr()
			}
			rl.AdminPort = port
		case 0:

		default:
			return nil, h.ArgErr()
		}

		for h.NextBlock(0) {
			switch h.Val() {
			case "admin_port":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				port, err := strconv.Atoi(h.Val())
				if err != nil {
					return nil, h.ArgErr()
				}
				rl.AdminPort = port

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
            font-family: Arial, sans-serif;
            background-color: #121212;
            color: white;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container {
            max-width: 600px;
            width: 90%;
            padding: 30px;
            border: 1px solid #333;
            border-radius: 8px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.5);
            text-align: center;
        }
        h1 {
            color: #f24b4b;
            margin-bottom: 30px;
            font-size: 2.2rem;
        }
        p {
            margin-bottom: 20px;
            line-height: 1.6;
            font-size: 1.1rem;
        }
        .octagon {
            width: 80px;
            height: 80px;
            background-color: #f24b4b;
            position: relative;
            margin: 0 auto 30px;
            clip-path: polygon(30% 0%, 70% 0%, 100% 30%, 100% 70%, 70% 100%, 30% 100%, 0% 70%, 0% 30%);
        }
        .details {
            background-color: #1e1e1e;
            border-radius: 6px;
            padding: 15px;
            margin: 30px 0;
            text-align: left;
        }
        .detail-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
        }
        .countdown {
            font-size: 2rem;
            color: #f24b4b;
            font-weight: bold;
            margin: 20px 0;
        }
        .countdown-container {
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="octagon"></div>
        <h1>Ваш IP адрес заблокирован</h1>
        <p>
            Наша система обнаружила необычно большое количество запросов с вашего IP-адреса. В целях безопасности мы временно ограничили доступ к сайту.
        </p>
        
        <div class="details">
            <div class="detail-item">
                <span>IP адрес:</span>
                <span>{{.IP}}</span>
            </div>
            <div class="detail-item">
                <span>Причина блокировки:</span>
                <span>{{.BlockReason}}</span>
            </div>
            <div class="detail-item">
                <span>Лимит запросов:</span>
                <span>{{.RequestLimit}} в секунду</span>
            </div>
            <div class="detail-item">
                <span>Время блокировки:</span>
                <span>{{.BlockDuration}} минут</span>
            </div>
        </div>
        
        <div class="countdown-container">
            <h2>Блокировка будет снята через:</h2>
            <div class="countdown">
                <span id="timer">{{.TotalRemaining}}</span>
            </div>
        </div>
        
        <p>После окончания блокировки вы сможете продолжить использование сайта без ограничений.</p>
        
        <footer style="text-align: center; margin-top: 30px; padding: 15px; border-top: 1px solid #333; color: #888;">
            <p>Под защитой <strong>c0re</strong> | <a href="https://c0rex86.ru" style="color: #f24b4b; text-decoration: none;" target="_blank">c0rex86.ru</a></p>
        </footer>
    </div>

    <script>
        // Countdown timer script
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
