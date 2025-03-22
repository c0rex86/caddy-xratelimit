package xratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"go.uber.org/zap"
)

type adminServer struct {
	rateLimit *RateLimit
	server    *http.Server
	port      int
	logger    *zap.Logger
}

// AdminStats contains statistics for the admin panel.
type AdminStats struct {
	TotalVisitors     int                    `json:"total_visitors"`
	BlockedVisitors   int                    `json:"blocked_visitors"`
	VisitorDetails    map[string]VisitorInfo `json:"visitor_details"`
	RequestsPerSecond int                    `json:"requests_per_second"`
	BlockDuration     string                 `json:"block_duration"`
	WhitelistedIPs    []string               `json:"whitelisted_ips"`
	BlacklistedIPs    []string               `json:"blacklisted_ips"`

	// Advanced statistics
	TotalRequests       int64            `json:"total_requests"`
	TotalBlocked        int64            `json:"total_blocked"`
	TotalWhitelisted    int64            `json:"total_whitelisted"`
	TotalBlacklisted    int64            `json:"total_blacklisted"`
	RequestsPerInterval map[string]int64 `json:"requests_per_interval"`
	BlocksPerInterval   map[string]int64 `json:"blocks_per_interval"`
	TopVisitors         map[string]int64 `json:"top_visitors"`
}

type VisitorInfo struct {
	IP            string    `json:"ip"`
	RequestCount  int       `json:"request_count"`
	LastSeen      time.Time `json:"last_seen"`
	Blocked       bool      `json:"blocked"`
	BlockedAt     time.Time `json:"blocked_at,omitempty"`
	BlockedUntil  time.Time `json:"blocked_until,omitempty"`
	RemainingTime string    `json:"remaining_time,omitempty"`
}

func newAdminServer(rl *RateLimit, port int, logger *zap.Logger) *adminServer {
	return &adminServer{
		rateLimit: rl,
		port:      port,
		logger:    logger,
	}
}

func (as *adminServer) start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", as.handleIndex)
	mux.HandleFunc("/api/stats", as.handleStats)
	mux.HandleFunc("/api/config", as.handleConfig)
	mux.HandleFunc("/api/unblock", as.handleUnblock)
	mux.HandleFunc("/api/whitelist", as.handleWhitelist)
	mux.HandleFunc("/api/blacklist", as.handleBlacklist)
	mux.HandleFunc("/api/metrics", as.handleMetrics)

	as.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", as.port),
		Handler: mux,
	}

	as.logger.Info("Starting admin server", zap.Int("port", as.port))
	return as.server.ListenAndServe()
}

func (as *adminServer) stop() error {
	if as.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return as.server.Shutdown(ctx)
	}
	return nil
}

func (as *adminServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(adminIndexHTML))
}

func (as *adminServer) handleStats(w http.ResponseWriter, r *http.Request) {
	as.rateLimit.mu.RLock()
	defer as.rateLimit.mu.RUnlock()

	stats := AdminStats{
		TotalVisitors:     len(as.rateLimit.visitors),
		BlockedVisitors:   0,
		VisitorDetails:    make(map[string]VisitorInfo),
		RequestsPerSecond: as.rateLimit.RequestsPerSecond,
		BlockDuration:     as.rateLimit.BlockDuration,
	}

	as.rateLimit.stats.RLock()
	stats.TotalRequests = as.rateLimit.stats.totalRequests
	stats.TotalBlocked = as.rateLimit.stats.totalBlocked
	stats.TotalWhitelisted = as.rateLimit.stats.totalWhitelisted
	stats.TotalBlacklisted = as.rateLimit.stats.totalBlacklisted

	stats.RequestsPerInterval = make(map[string]int64)
	for k, v := range as.rateLimit.stats.requestsPerInterval {
		stats.RequestsPerInterval[k] = v
	}

	stats.BlocksPerInterval = make(map[string]int64)
	for k, v := range as.rateLimit.stats.blocksPerInterval {
		stats.BlocksPerInterval[k] = v
	}

	stats.TopVisitors = make(map[string]int64)
	for k, v := range as.rateLimit.stats.topVisitors {
		stats.TopVisitors[k] = v
	}
	as.rateLimit.stats.RUnlock()

	whitelistedIPs := make([]string, 0, len(as.rateLimit.whitelist))
	for ip := range as.rateLimit.whitelist {
		whitelistedIPs = append(whitelistedIPs, ip)
	}
	stats.WhitelistedIPs = whitelistedIPs

	blacklistedIPs := make([]string, 0, len(as.rateLimit.blacklist))
	for ip := range as.rateLimit.blacklist {
		blacklistedIPs = append(blacklistedIPs, ip)
	}
	stats.BlacklistedIPs = blacklistedIPs

	now := time.Now()
	for ip, v := range as.rateLimit.visitors {
		isBlocked := v.blocked && now.Before(v.unblockAt)
		if isBlocked {
			stats.BlockedVisitors++
		}

		var remainingTime string
		if isBlocked {
			remaining := v.unblockAt.Sub(now)
			minutes := int(remaining.Minutes())
			seconds := int(remaining.Seconds()) % 60
			remainingTime = fmt.Sprintf("%d:%02d", minutes, seconds)
		}

		stats.VisitorDetails[ip] = VisitorInfo{
			IP:            ip,
			RequestCount:  v.count,
			LastSeen:      v.lastSeen,
			Blocked:       isBlocked,
			BlockedAt:     v.blockedAt,
			BlockedUntil:  v.unblockAt,
			RemainingTime: remainingTime,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (as *adminServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Update requests per second
	if rps := r.FormValue("requests_per_second"); rps != "" {
		rpsInt, err := strconv.Atoi(rps)
		if err != nil || rpsInt <= 0 {
			http.Error(w, "Invalid requests per second", http.StatusBadRequest)
			return
		}
		as.rateLimit.mu.Lock()
		as.rateLimit.RequestsPerSecond = rpsInt
		as.rateLimit.mu.Unlock()
	}

	// Update block duration
	if blockDuration := r.FormValue("block_duration"); blockDuration != "" {
		duration, err := time.ParseDuration(blockDuration)
		if err != nil || duration <= 0 {
			http.Error(w, "Invalid block duration", http.StatusBadRequest)
			return
		}
		as.rateLimit.mu.Lock()
		as.rateLimit.BlockDuration = blockDuration
		as.rateLimit.blockDuration = duration
		as.rateLimit.mu.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"success"}`))
}

// handleUnblock unblocks a visitor.
func (as *adminServer) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := r.FormValue("ip")
	if ip == "" {
		http.Error(w, "IP address required", http.StatusBadRequest)
		return
	}

	// Unblock the IP
	as.rateLimit.mu.Lock()
	if v, exists := as.rateLimit.visitors[ip]; exists {
		v.blocked = false
		v.count = 0
	}
	as.rateLimit.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"success"}`))
}

// handleWhitelist adds or removes an IP from the whitelist.
func (as *adminServer) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	ip := r.FormValue("ip")
	if ip == "" {
		http.Error(w, "IP address required", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action")
	if action != "add" && action != "remove" {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	as.rateLimit.mu.Lock()
	if action == "add" {
		as.rateLimit.whitelist[ip] = true
		delete(as.rateLimit.blacklist, ip)
	} else {
		delete(as.rateLimit.whitelist, ip)
	}
	as.rateLimit.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"success"}`))
}

func (as *adminServer) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	ip := r.FormValue("ip")
	if ip == "" {
		http.Error(w, "IP address required", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action")
	if action != "add" && action != "remove" {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	as.rateLimit.mu.Lock()
	if action == "add" {
		as.rateLimit.blacklist[ip] = true

		delete(as.rateLimit.whitelist, ip)
	} else {
		delete(as.rateLimit.blacklist, ip)
	}
	as.rateLimit.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"success"}`))
}

func (as *adminServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	as.rateLimit.stats.RLock()
	defer as.rateLimit.stats.RUnlock()

	metrics := struct {
		RequestsPerInterval map[string]int64 `json:"requests_per_interval"`
		BlocksPerInterval   map[string]int64 `json:"blocks_per_interval"`
		TotalRequests       int64            `json:"total_requests"`
		TotalBlocked        int64            `json:"total_blocked"`
		TotalWhitelisted    int64            `json:"total_whitelisted"`
		TotalBlacklisted    int64            `json:"total_blacklisted"`
		TopVisitors         map[string]int64 `json:"top_visitors"`
	}{
		RequestsPerInterval: make(map[string]int64),
		BlocksPerInterval:   make(map[string]int64),
		TotalRequests:       as.rateLimit.stats.totalRequests,
		TotalBlocked:        as.rateLimit.stats.totalBlocked,
		TotalWhitelisted:    as.rateLimit.stats.totalWhitelisted,
		TotalBlacklisted:    as.rateLimit.stats.totalBlacklisted,
		TopVisitors:         make(map[string]int64),
	}

	for k, v := range as.rateLimit.stats.requestsPerInterval {
		metrics.RequestsPerInterval[k] = v
	}

	for k, v := range as.rateLimit.stats.blocksPerInterval {
		metrics.BlocksPerInterval[k] = v
	}

	for k, v := range as.rateLimit.stats.topVisitors {
		metrics.TopVisitors[k] = v
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// Admin panel HTML template
const adminIndexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XRateLimit Admin Panel</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #121212;
            color: white;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #1e1e1e;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        h1, h2, h3 {
            color: #f24b4b;
        }
        .stats-container {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .stat-card {
            background-color: #1e1e1e;
            border-radius: 8px;
            padding: 20px;
            flex: 1;
            text-align: center;
            min-width: 200px;
        }
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            margin: 10px 0;
        }
        .config-panel {
            background-color: #1e1e1e;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .visitor-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .visitor-table th, .visitor-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #333;
        }
        .visitor-table th {
            background-color: #2a2a2a;
        }
        .visitor-table tr:hover {
            background-color: #2a2a2a;
        }
        button, input, select {
            padding: 8px 16px;
            border-radius: 4px;
            border: none;
            background-color: #333;
            color: white;
            cursor: pointer;
        }
        button:hover {
            background-color: #444;
        }
        button.unblock {
            background-color: #f24b4b;
        }
        button.unblock:hover {
            background-color: #e03a3a;
        }
        button.whitelist {
            background-color: #4CAF50;
        }
        button.whitelist:hover {
            background-color: #45a049;
        }
        button.blacklist {
            background-color: #607D8B;
        }
        button.blacklist:hover {
            background-color: #546E7A;
        }
        .blocked {
            color: #f24b4b;
            font-weight: bold;
        }
        .whitelisted {
            color: #4CAF50;
            font-weight: bold;
        }
        .blacklisted {
            color: #607D8B;
            font-weight: bold;
        }
        input, select {
            margin-right: 10px;
            background-color: #333;
            color: white;
        }
        form {
            display: flex;
            gap: 10px;
            align-items: center;
            margin-bottom: 15px;
        }
        label {
            margin-right: 5px;
        }
        .refresh {
            margin-left: auto;
            background-color: #4caf50;
        }
        .refresh:hover {
            background-color: #3d8b40;
        }
        .actions {
            display: flex;
            gap: 10px;
        }
        .ip-list-panel {
            background-color: #1e1e1e;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .ip-list {
            max-height: 200px;
            overflow-y: auto;
            margin-top: 15px;
            border: 1px solid #333;
            border-radius: 4px;
            padding: 10px;
        }
        .ip-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 5px 0;
            border-bottom: 1px solid #333;
        }
        .ip-item:last-child {
            border-bottom: none;
        }
        .tabs {
            display: flex;
            margin-bottom: 20px;
        }
        .tab {
            padding: 10px 20px;
            background-color: #2a2a2a;
            border-radius: 4px 4px 0 0;
            margin-right: 5px;
            cursor: pointer;
        }
        .tab.active {
            background-color: #1e1e1e;
            font-weight: bold;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .flex-row {
            display: flex;
            gap: 20px;
        }
        .flex-column {
            flex: 1;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>XRateLimit Admin Panel</h1>
            <button id="refresh-btn" class="refresh">Refresh Data</button>
        </header>
        
        <div class="stats-container">
            <div class="stat-card">
                <h3>Total Visitors</h3>
                <div class="stat-value" id="total-visitors">0</div>
            </div>
            <div class="stat-card">
                <h3>Blocked Visitors</h3>
                <div class="stat-value" id="blocked-visitors">0</div>
            </div>
            <div class="stat-card">
                <h3>Requests Per Second</h3>
                <div class="stat-value" id="requests-per-second">10</div>
            </div>
            <div class="stat-card">
                <h3>Block Duration</h3>
                <div class="stat-value" id="block-duration">5m</div>
            </div>
            <div class="stat-card">
                <h3>Whitelisted IPs</h3>
                <div class="stat-value" id="whitelisted-count">0</div>
            </div>
            <div class="stat-card">
                <h3>Blacklisted IPs</h3>
                <div class="stat-value" id="blacklisted-count">0</div>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab active" data-tab="visitors">Visitors</div>
            <div class="tab" data-tab="config">Configuration</div>
            <div class="tab" data-tab="lists">IP Lists</div>
        </div>
        
        <div class="tab-content active" id="visitors-tab">
            <h2>Visitor List</h2>
            <table class="visitor-table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Request Count</th>
                        <th>Last Seen</th>
                        <th>Status</th>
                        <th>Remaining Block Time</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="visitor-table-body">
                </tbody>
            </table>
        </div>
        
        <div class="tab-content" id="config-tab">
            <div class="config-panel">
                <h2>Rate Limit Configuration</h2>
                <form id="config-form">
                    <div>
                        <label for="requests-per-second-input">Requests Per Second:</label>
                        <input type="number" id="requests-per-second-input" name="requests_per_second" min="1" value="10">
                    </div>
                    <div>
                        <label for="block-duration-input">Block Duration:</label>
                        <select id="block-duration-input" name="block_duration">
                            <option value="1m">1 minute</option>
                            <option value="5m" selected>5 minutes</option>
                            <option value="10m">10 minutes</option>
                            <option value="30m">30 minutes</option>
                            <option value="1h">1 hour</option>
                            <option value="6h">6 hours</option>
                            <option value="12h">12 hours</option>
                            <option value="24h">24 hours</option>
                        </select>
                    </div>
                    <button type="submit">Save Configuration</button>
                </form>
            </div>
        </div>
        
        <div class="tab-content" id="lists-tab">
            <div class="flex-row">
                <div class="flex-column">
                    <div class="ip-list-panel">
                        <h2>Whitelist</h2>
                        <p>Whitelisted IPs bypass all rate limiting.</p>
                        <form id="whitelist-form">
                            <input type="text" id="whitelist-ip-input" name="ip" placeholder="Enter IP address" pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}$">
                            <button type="submit">Add to Whitelist</button>
                        </form>
                        <div class="ip-list" id="whitelist-container">
                        </div>
                    </div>
                </div>
                
                <div class="flex-column">
                    <div class="ip-list-panel">
                        <h2>Blacklist</h2>
                        <p>Blacklisted IPs are always blocked.</p>
                        <form id="blacklist-form">
                            <input type="text" id="blacklist-ip-input" name="ip" placeholder="Enter IP address" pattern="^([0-9]{1,3}\.){3}[0-9]{1,3}$">
                            <button type="submit">Add to Blacklist</button>
                        </form>
                        <div class="ip-list" id="blacklist-container">
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <footer style="text-align: center; margin-top: 30px; padding: 15px; border-top: 1px solid #333; color: #888;">
            <p>Под защитой <strong>c0re</strong> | <a href="https://c0rex86.ru" style="color: #f24b4b; text-decoration: none;" target="_blank">c0rex86.ru</a></p>
        </footer>
    </div>

    <script>
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                this.classList.add('active');
                
                document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
                document.getElementById(this.dataset.tab + '-tab').classList.add('active');
            });
        });
        
        function fetchStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-visitors').textContent = data.total_visitors;
                    document.getElementById('blocked-visitors').textContent = data.blocked_visitors;
                    document.getElementById('requests-per-second').textContent = data.requests_per_second;
                    document.getElementById('block-duration').textContent = data.block_duration;
                    document.getElementById('whitelisted-count').textContent = data.whitelisted_ips ? data.whitelisted_ips.length : 0;
                    document.getElementById('blacklisted-count').textContent = data.blacklisted_ips ? data.blacklisted_ips.length : 0;
                    
                    document.getElementById('requests-per-second-input').value = data.requests_per_second;
                    if (data.block_duration) {
                        const blockDurationSelect = document.getElementById('block-duration-input');
                        for (let i = 0; i < blockDurationSelect.options.length; i++) {
                            if (blockDurationSelect.options[i].value === data.block_duration) {
                                blockDurationSelect.selectedIndex = i;
                                break;
                            }
                        }
                    }
                    
                    const tableBody = document.getElementById('visitor-table-body');
                    tableBody.innerHTML = '';
                    
                    Object.entries(data.visitor_details).forEach(([ip, info]) => {
                        const row = document.createElement('tr');
                        
                        const ipCell = document.createElement('td');
                        ipCell.textContent = ip;
                        row.appendChild(ipCell);
                        
                        const requestCountCell = document.createElement('td');
                        requestCountCell.textContent = info.request_count;
                        row.appendChild(requestCountCell);
                        
                        const lastSeenCell = document.createElement('td');
                        lastSeenCell.textContent = new Date(info.last_seen).toLocaleString();
                        row.appendChild(lastSeenCell);
                        
                        const statusCell = document.createElement('td');
                        if (data.whitelisted_ips && data.whitelisted_ips.includes(ip)) {
                            statusCell.textContent = 'Whitelisted';
                            statusCell.classList.add('whitelisted');
                        } else if (data.blacklisted_ips && data.blacklisted_ips.includes(ip)) {
                            statusCell.textContent = 'Blacklisted';
                            statusCell.classList.add('blacklisted');
                        } else if (info.blocked) {
                            statusCell.textContent = 'Blocked';
                            statusCell.classList.add('blocked');
                        } else {
                            statusCell.textContent = 'Active';
                        }
                        row.appendChild(statusCell);
                        
                        const remainingTimeCell = document.createElement('td');
                        remainingTimeCell.textContent = info.remaining_time || '-';
                        row.appendChild(remainingTimeCell);
                        
                        const actionsCell = document.createElement('td');
                        actionsCell.classList.add('actions');
                        
                        if (info.blocked) {
                            const unblockBtn = document.createElement('button');
                            unblockBtn.textContent = 'Unblock';
                            unblockBtn.classList.add('unblock');
                            unblockBtn.onclick = () => unblockIP(ip);
                            actionsCell.appendChild(unblockBtn);
                        }
                        
                        if (!data.whitelisted_ips || !data.whitelisted_ips.includes(ip)) {
                            const whitelistBtn = document.createElement('button');
                            whitelistBtn.textContent = 'Whitelist';
                            whitelistBtn.classList.add('whitelist');
                            whitelistBtn.onclick = () => whitelistIP(ip);
                            actionsCell.appendChild(whitelistBtn);
                        }
                        
                        if (!data.blacklisted_ips || !data.blacklisted_ips.includes(ip)) {
                            const blacklistBtn = document.createElement('button');
                            blacklistBtn.textContent = 'Blacklist';
                            blacklistBtn.classList.add('blacklist');
                            blacklistBtn.onclick = () => blacklistIP(ip);
                            actionsCell.appendChild(blacklistBtn);
                        }
                        
                        if (actionsCell.children.length === 0) {
                            actionsCell.textContent = '-';
                        }
                        
                        row.appendChild(actionsCell);
                        tableBody.appendChild(row);
                    });
                    
                    const whitelistContainer = document.getElementById('whitelist-container');
                    whitelistContainer.innerHTML = '';
                    
                    if (data.whitelisted_ips && data.whitelisted_ips.length > 0) {
                        data.whitelisted_ips.forEach(ip => {
                            const ipItem = document.createElement('div');
                            ipItem.classList.add('ip-item');
                            
                            const ipText = document.createElement('span');
                            ipText.textContent = ip;
                            ipItem.appendChild(ipText);
                            
                            const removeBtn = document.createElement('button');
                            removeBtn.textContent = 'Remove';
                            removeBtn.onclick = () => removeFromWhitelist(ip);
                            ipItem.appendChild(removeBtn);
                            
                            whitelistContainer.appendChild(ipItem);
                        });
                    } else {
                        whitelistContainer.innerHTML = '<p>No whitelisted IPs</p>';
                    }
                    
                    const blacklistContainer = document.getElementById('blacklist-container');
                    blacklistContainer.innerHTML = '';
                    
                    if (data.blacklisted_ips && data.blacklisted_ips.length > 0) {
                        data.blacklisted_ips.forEach(ip => {
                            const ipItem = document.createElement('div');
                            ipItem.classList.add('ip-item');
                            
                            const ipText = document.createElement('span');
                            ipText.textContent = ip;
                            ipItem.appendChild(ipText);
                            
                            const removeBtn = document.createElement('button');
                            removeBtn.textContent = 'Remove';
                            removeBtn.onclick = () => removeFromBlacklist(ip);
                            ipItem.appendChild(removeBtn);
                            
                            blacklistContainer.appendChild(ipItem);
                        });
                    } else {
                        blacklistContainer.innerHTML = '<p>No blacklisted IPs</p>';
                    }
                })
                .catch(error => console.error('Error fetching stats:', error));
        }
        
        function unblockIP(ip) {
            const formData = new FormData();
            formData.append('ip', ip);
            
            fetch('/api/unblock', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    fetchStats();
                }
            })
            .catch(error => console.error('Error unblocking IP:', error));
        }
        
        function whitelistIP(ip) {
            const formData = new FormData();
            formData.append('ip', ip);
            formData.append('action', 'add');
            
            fetch('/api/whitelist', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    fetchStats();
                }
            })
            .catch(error => console.error('Error whitelisting IP:', error));
        }
        
        function removeFromWhitelist(ip) {
            const formData = new FormData();
            formData.append('ip', ip);
            formData.append('action', 'remove');
            
            fetch('/api/whitelist', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    fetchStats();
                }
            })
            .catch(error => console.error('Error removing from whitelist:', error));
        }
        
        function blacklistIP(ip) {
            const formData = new FormData();
            formData.append('ip', ip);
            formData.append('action', 'add');
            
            fetch('/api/blacklist', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    fetchStats();
                }
            })
            .catch(error => console.error('Error blacklisting IP:', error));
        }
        
        function removeFromBlacklist(ip) {
            const formData = new FormData();
            formData.append('ip', ip);
            formData.append('action', 'remove');
            
            fetch('/api/blacklist', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    fetchStats();
                }
            })
            .catch(error => console.error('Error removing from blacklist:', error));
        }
        
        document.getElementById('whitelist-form').addEventListener('submit', function(e) {
            e.preventDefault();
            const ip = document.getElementById('whitelist-ip-input').value;
            if (ip) {
                whitelistIP(ip);
                document.getElementById('whitelist-ip-input').value = '';
            }
        });
        
        document.getElementById('blacklist-form').addEventListener('submit', function(e) {
            e.preventDefault();
            const ip = document.getElementById('blacklist-ip-input').value;
            if (ip) {
                blacklistIP(ip);
                document.getElementById('blacklist-ip-input').value = '';
            }
        });
        
        document.getElementById('config-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            
            fetch('/api/config', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    fetchStats();
                }
            })
            .catch(error => console.error('Error saving configuration:', error));
        });
        
        document.getElementById('refresh-btn').addEventListener('click', fetchStats);
        
        document.addEventListener('DOMContentLoaded', fetchStats);
        
        setInterval(fetchStats, 5000);
    </script>
</body>
</html>`
