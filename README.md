# Xratelimit - Caddy Rate Limiting Plugin



```bash
xcaddy build --with github.com/c0rex86/xrate@latest
```


```bash
xcaddy build
```

## Usage

### Basic Caddyfile Configuration

```
{
    order xratelimit before respond
}

localhost {
    # Basic usage with defaults (10 requests per second, 5 minute block)
    xratelimit

    # Rest of your site configuration
    file_server
}
```

### Advanced Configuration

```
localhost {
    # Configure with specific parameters:
    # xratelimit [requests_per_second] [block_duration] [admin_port]
    xratelimit 15 10m 6666

    # Or using block syntax with whitelist and blacklist
    # xratelimit 15 {
    #     admin_port 7777
    #     whitelist 127.0.0.1 192.168.1.100
    #     blacklist 192.168.1.200 203.0.113.1
    # }

    file_server
}
```

## Directive Syntax

The `xratelimit` directive can be used in multiple ways:

1. **Basic**: `xratelimit` - Uses default settings (10 req/sec, 5 min block, admin on port 6666)
2. **With parameters**: `xratelimit [requests_per_second] [block_duration] [admin_port]`
   - `requests_per_second`: Maximum requests allowed per second (default: 10)
   - `block_duration`: Duration of the block when limit is exceeded (default: "5m")
   - `admin_port`: Port for the admin web interface (default: 6666)
3. **With block**:
   ```
   xratelimit [requests_per_second] {
       admin_port [port]
       whitelist [ip1] [ip2] ...
       blacklist [ip1] [ip2] ...
   }
   ```

## Whitelist and Blacklist

Whitelists and blacklists can be configured in the Caddyfile or managed via the admin interface.

- **Whitelist**: IPs that bypass rate limiting entirely (useful for your own servers, administrators, etc.)
- **Blacklist**: IPs that are always blocked regardless of request rate (for known malicious actors)

Example in Caddyfile:

```
api.localhost {
    xratelimit 20 30m {
        # Allow internal network and specific IPs
        whitelist 127.0.0.1 10.0.0.0/8 192.168.0.0/16
        # Block known bad actors
        blacklist 198.51.100.0/24
    }
    
    respond "API endpoint"
}
```

## Admin Interface

The admin interface is accessible at `http://localhost:6666` (or your configured port) and provides:

- Overall statistics dashboard
- List of visitors with their request counts and status
- Ability to unblock IPs manually
- Configuration interface to adjust rate limits and block durations
- Whitelist and blacklist management
- Real-time updates of visitor activities

## Block Page Customization

You can customize the block page by creating a template file at:

```
<caddy_dir>/xratelimit/templates/block.html
```

If this file is not found, the default built-in template will be used.

## License

MIT

## Author

c0rex86 - [https://c0rex86.ru](https://c0rex86.ru)
GitHub: [https://github.com/c0rex86/](https://github.com/c0rex86/) 