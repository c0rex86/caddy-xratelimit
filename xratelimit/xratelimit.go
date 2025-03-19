package xratelimit

import (
	"bytes"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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

	visitors      map[string]*visitor
	whitelist     map[string]bool
	blacklist     map[string]bool
	blockDuration time.Duration
	adminServer   *adminServer
	mu            sync.RWMutex
	logger        *zap.Logger
	blockPageTmpl *template.Template
	
	stats struct {
		sync.RWMutex
		totalRequests       int64
		totalBlocked        int64
		totalWhitelisted    int64
		totalBlacklisted    int64
		requestsPerInterval map[string]int64
		blocksPerInterval   map[string]int64
		topVisitors         map[string]int64
		lastCleanup         time.Time
	}
}

type visitor struct {
	ip        string
	count     int
	blocked   bool
	lastSeen  time.Time
	blockedAt time.Time
	unblockAt time.Time
}

func (rl *RateLimit) CaddyModule() caddy.ModuleInfo {
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
	rl.stats.lastCleanup = time.Now()
	
	if rl.RequestsPerSecond == 0 {
		rl.RequestsPerSecond = 10
	}
	
	if rl.BlockDuration == "" {
		rl.BlockDuration = "5m"
	}
	
	var err error
	rl.blockDuration, err = time.ParseDuration(rl.BlockDuration)
	if err != nil {
		return fmt.Errorf("invalid block duration: %v", err)
	}
	
	if rl.AdminPort == 0 {
		rl.AdminPort = 6666
	}
	
	rl.blockPageTmpl, err = template.New("block").Parse(blockPageTemplate)
	if err != nil {
		return fmt.Errorf("error parsing block page template: %v", err)
	}
	
	for _, ip := range rl.WhitelistIPs {
		rl.whitelist[ip] = true
	}
	
	for _, ip := range rl.BlacklistIPs {
		rl.blacklist[ip] = true
	}
	
	go rl.collectStats()
	
	rl.adminServer = newAdminServer(rl, rl.AdminPort, rl.logger)
	go func() {
		if err := rl.adminServer.start(); err != nil && err != http.ErrServerClosed {
			rl.logger.Error("admin server error", zap.Error(err))
		}
	}()
	
	return nil
}

func (rl *RateLimit) Cleanup() error {
	if rl.adminServer != nil {
		return rl.adminServer.stop()
	}
	return nil
}

func (rl *RateLimit) collectStats() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		now := time.Now()
		timeKey := now.Format("15:04")
		
		rl.stats.Lock()
		
		rl.stats.requestsPerInterval[timeKey] = 0
		rl.stats.blocksPerInterval[timeKey] = 0
		
		if len(rl.stats.requestsPerInterval) > 60 {
			for k := range rl.stats.requestsPerInterval {
				if t, err := time.Parse("15:04", k); err == nil {
					if now.Sub(t) > 24*time.Hour {
						delete(rl.stats.requestsPerInterval, k)
						delete(rl.stats.blocksPerInterval, k)
					}
				}
			}
		}
		
		if now.Sub(rl.stats.lastCleanup) > 1*time.Hour {
			rl.stats.lastCleanup = now
			
			if len(rl.stats.topVisitors) > 1000 {
				newTopVisitors := make(map[string]int64)
				for ip, count := range rl.stats.topVisitors {
					if count > 100 {
						newTopVisitors[ip] = count
					}
				}
				rl.stats.topVisitors = newTopVisitors
			}
		}
		
		rl.stats.Unlock()
	}
}

func (rl *RateLimit) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	
	timeKey := time.Now().Format("15:04")
	
	rl.stats.Lock()
	rl.stats.totalRequests++
	rl.stats.requestsPerInterval[timeKey]++
	rl.stats.topVisitors[ip]++
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
		rl.stats.blocksPerInterval[timeKey]++
		rl.stats.totalBlocked++
		rl.stats.Unlock()
		
		return rl.serveBlockPage(w, r, ip)
	}
	
	v, exists := rl.visitors[ip]
	rl.mu.RUnlock()
	
	now := time.Now()
	rl.mu.Lock()
	
	if !exists {
		rl.visitors[ip] = &visitor{
			ip:       ip,
			count:    1,
			lastSeen: now,
		}
		rl.mu.Unlock()
		return next.ServeHTTP(w, r)
	}
	
	if v.blocked {
		if now.After(v.unblockAt) {
			v.blocked = false
			v.count = 1
			v.lastSeen = now
			rl.mu.Unlock()
			return next.ServeHTTP(w, r)
		}
		
		rl.mu.Unlock()
		
		rl.stats.Lock()
		rl.stats.blocksPerInterval[timeKey]++
		rl.stats.totalBlocked++
		rl.stats.Unlock()
		
		return rl.serveBlockPage(w, r, ip)
	}
	
	timeSince := now.Sub(v.lastSeen).Seconds()
	rate := float64(v.count) / timeSince
	
	if timeSince > 60 {
		v.count = 1
		v.lastSeen = now
		rl.mu.Unlock()
		return next.ServeHTTP(w, r)
	}
	
	if rate > float64(rl.RequestsPerSecond) {
		v.blocked = true
		v.blockedAt = now
		v.unblockAt = now.Add(rl.blockDuration)
		rl.mu.Unlock()
		
		rl.stats.Lock()
		rl.stats.blocksPerInterval[timeKey]++
		rl.stats.totalBlocked++
		rl.stats.Unlock()
		
		return rl.serveBlockPage(w, r, ip)
	}
	
	v.count++
	v.lastSeen = now
	rl.mu.Unlock()
	
	return next.ServeHTTP(w, r)
}

func (rl *RateLimit) serveBlockPage(w http.ResponseWriter, r *http.Request, ip string) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	
	rl.mu.RLock()
	v := rl.visitors[ip]
	
	var remainingTime string
	var remainingSeconds int
	
	if v != nil && v.blocked {
		remaining := v.unblockAt.Sub(time.Now())
		minutes := int(remaining.Minutes())
		seconds := int(remaining.Seconds()) % 60
		remainingTime = fmt.Sprintf("%d:%02d", minutes, seconds)
		remainingSeconds = int(remaining.Seconds())
	}
	
	blockData := struct {
		IP              string
		RemainingTime   string
		RemainingSeconds int
		RequestsPerSecond int
		BlockDuration    string
	}{
		IP:               ip,
		RemainingTime:    remainingTime,
		RemainingSeconds: remainingSeconds,
		RequestsPerSecond: rl.RequestsPerSecond,
		BlockDuration:     rl.BlockDuration,
	}
	rl.mu.RUnlock()
	
	var buf bytes.Buffer
	if err := rl.blockPageTmpl.Execute(&buf, blockData); err != nil {
		rl.logger.Error("error executing block page template", zap.Error(err))
		return err
	}
	
	w.Write(buf.Bytes())
	return nil
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
				for h.NextArg() {
					rl.WhitelistIPs = append(rl.WhitelistIPs, h.Val())
				}
			case "blacklist":
				for h.NextArg() {
					rl.BlacklistIPs = append(rl.BlacklistIPs, h.Val())
				}
			default:
				return nil, h.Errf("unknown subdirective '%s'", h.Val())
			}
		}
	}
	
	return &rl, nil
}

func (rl *RateLimit) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		switch len(args) {
		case 1:
			rps, err := strconv.Atoi(args[0])
			if err != nil {
				return d.ArgErr()
			}
			rl.RequestsPerSecond = rps
		case 2:
			rps, err := strconv.Atoi(args[0])
			if err != nil {
				return d.ArgErr()
			}
			rl.RequestsPerSecond = rps
			rl.BlockDuration = args[1]
		case 0:
		default:
			return d.ArgErr()
		}
		
		for d.NextBlock(0) {
			switch d.Val() {
			case "admin_port":
				if !d.NextArg() {
					return d.ArgErr()
				}
				port, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.ArgErr()
				}
				rl.AdminPort = port
			case "whitelist":
				for d.NextArg() {
					ip := d.Val()
					if strings.TrimSpace(ip) != "" {
						rl.WhitelistIPs = append(rl.WhitelistIPs, ip)
					}
				}
			case "blacklist":
				for d.NextArg() {
					ip := d.Val()
					if strings.TrimSpace(ip) != "" {
						rl.BlacklistIPs = append(rl.BlacklistIPs, ip)
					}
				}
			default:
				return d.Errf("unknown subdirective '%s'", d.Val())
			}
		}
	}
	
	return nil
}

var (
	_ caddy.Provisioner           = (*RateLimit)(nil)
	_ caddy.CleanerUpper          = (*RateLimit)(nil)
	_ caddyhttp.MiddlewareHandler = (*RateLimit)(nil)
	_ caddyfile.Unmarshaler       = (*RateLimit)(nil)
)

const blockPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rate Limit Exceeded</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f8f9fa;
            color: #343a40;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            padding: 0;
        }
        .container {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            padding: 2rem;
            max-width: 600px;
            text-align: center;
        }
        h1 {
            color: #dc3545;
            margin-top: 0;
        }
        .info {
            margin: 1.5rem 0;
            font-size: 1.1rem;
            line-height: 1.5;
        }
        .timer {
            font-size: 1.5rem;
            font-weight: bold;
            margin: 1rem 0;
            color: #343a40;
        }
        .progress-container {
            width: 100%;
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            margin: 1.5rem 0;
            overflow: hidden;
        }
        .progress-bar {
            height: 100%;
            background-color: #dc3545;
            border-radius: 10px;
            transition: width 1s linear;
        }
        .details {
            background-color: #f8f9fa;
            border-radius: 4px;
            padding: 1rem;
            margin-top: 1.5rem;
            font-size: 0.9rem;
            text-align: left;
        }
        .details p {
            margin: 0.5rem 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Rate Limit Exceeded</h1>
        <div class="info">
            <p>Your IP address ({{.IP}}) has exceeded the allowed rate of {{.RequestsPerSecond}} requests per second.</p>
            <p>Access to this server has been temporarily blocked.</p>
        </div>
        <div class="timer" id="timer">{{.RemainingTime}}</div>
        <div class="progress-container">
            <div class="progress-bar" id="progress-bar"></div>
        </div>
        <p>Please wait until the block expires or contact the site administrator if you believe this is an error.</p>
        <div class="details">
            <p><strong>IP Address:</strong> {{.IP}}</p>
            <p><strong>Block Duration:</strong> {{.BlockDuration}}</p>
        </div>
    </div>

    <script>
        const remainingSeconds = {{.RemainingSeconds}};
        const totalSeconds = remainingSeconds;
        let secondsLeft = remainingSeconds;
        
        function updateTimer() {
            if (secondsLeft <= 0) {
                document.getElementById('timer').textContent = "Unblocked";
                setTimeout(() => { window.location.reload(); }, 1000);
                return;
            }
            
            const minutes = Math.floor(secondsLeft / 60);
            const seconds = secondsLeft % 60;
            document.getElementById('timer').textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
            
            const progressPercent = 100 - ((secondsLeft / totalSeconds) * 100);
            document.getElementById('progress-bar').style.width = progressPercent + '%';
            
            secondsLeft--;
            setTimeout(updateTimer, 1000);
        }
        
        updateTimer();
    </script>
</body>
</html>` 