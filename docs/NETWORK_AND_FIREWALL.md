# Network Requirements and Firewall Configuration

This document provides information about ChatFilter's network requirements and how to configure it to work in corporate environments with restrictive firewalls.

## Network Requirements

### Telegram MTProto Protocol

ChatFilter uses Telegram's MTProto protocol to communicate with Telegram servers. Understanding the network requirements is essential for deployment in restricted environments.

#### Required Ports

Telegram's MTProto protocol uses the following ports:

**Primary Connection (TCP):**
- Port **443** (HTTPS) - Primary port, works in most corporate environments
- Port **80** (HTTP) - Fallback option

**Alternative Ports (if primary is blocked):**
- Port **5222** - XMPP-compatible port
- Ports **49000-65535** - High-numbered ports as fallback

**Recommendation:** Telegram primarily uses **port 443**, which is typically allowed by corporate firewalls as it's the standard HTTPS port. If your firewall blocks all outbound connections, you need to explicitly allow TCP connections to Telegram servers on port 443.

#### IP Addresses and Domains

Telegram uses multiple data centers worldwide. ChatFilter needs to connect to:

**Telegram Server Domains:**
- `*.telegram.org` - Main Telegram infrastructure
- `*.t.me` - Public links and CDN
- `flora.telegram.org` - DC1 (Miami)
- `venus.telegram.org` - DC2 (Amsterdam)
- `aurora.telegram.org` - DC3 (Miami)
- `vesta.telegram.org` - DC4 (Amsterdam)
- `pluto.telegram.org` - DC5 (Singapore)

**Telegram IPv4 Ranges:**
Telegram uses the following IP address ranges (subject to change):
- `149.154.160.0/20`
- `91.108.4.0/22`
- `91.108.8.0/22`
- `91.108.12.0/22`
- `91.108.16.0/22`
- `91.108.20.0/22`
- `91.108.56.0/22`

**Note:** Telegram may change these IP addresses. It's recommended to allow traffic based on domains rather than hardcoded IPs when possible.

### DNS Requirements

ChatFilter requires DNS resolution to connect to Telegram servers. Ensure your network allows:
- DNS queries to your configured DNS servers
- Resolution of `*.telegram.org` and `*.t.me` domains

## Corporate Firewall Scenarios

### Scenario 1: Standard Corporate Firewall

**Problem:** Outbound traffic restricted to standard ports (80, 443)

**Solution:** Telegram works by default, as it primarily uses port 443.

**Configuration:** No additional configuration needed.

### Scenario 2: Deep Packet Inspection (DPI)

**Problem:** Firewall performs deep packet inspection and blocks MTProto protocol traffic

**Solution:** Use a proxy server to tunnel MTProto traffic through allowed protocols.

**Configuration:** Configure SOCKS5 or HTTP proxy (see [Proxy Configuration](#proxy-configuration) below)

### Scenario 3: Whitelist-Only Firewall

**Problem:** Only specific domains/IPs are whitelisted

**Solution:** Request your IT team to whitelist Telegram domains and IP ranges.

**Whitelist Request Template:**
```
Service: ChatFilter (Telegram API client)
Purpose: [Your business purpose]
Protocol: HTTPS (TCP)
Ports: 443 (primary), 80 (fallback)
Domains: *.telegram.org, *.t.me
IP Ranges: 149.154.160.0/20, 91.108.4.0/22, 91.108.8.0/22,
           91.108.12.0/22, 91.108.16.0/22, 91.108.20.0/22, 91.108.56.0/22
```

### Scenario 4: Complete Lockdown

**Problem:** All direct external connections blocked, must use corporate proxy

**Solution:** Configure ChatFilter to use your corporate HTTP/SOCKS5 proxy.

**Configuration:** See [Using Corporate Proxy](#using-corporate-proxy) below.

## Proxy Configuration

ChatFilter supports SOCKS5 and HTTP proxies to bypass firewall restrictions. This is useful when:
- Corporate firewall blocks MTProto protocol
- Deep packet inspection interferes with Telegram traffic
- Direct connection to Telegram servers is not allowed
- You need to route through a specific gateway

### Proxy Types

#### SOCKS5 Proxy (Recommended)
- **Best for:** Maximum compatibility and performance
- **Features:** Full TCP support, DNS resolution through proxy
- **Use when:** You need reliable tunneling without protocol restrictions

#### HTTP Proxy
- **Best for:** Environments that only allow HTTP proxies
- **Features:** Works with HTTP CONNECT method
- **Use when:** SOCKS5 is not available

### Configuration Methods

#### Method 1: Web Interface (Recommended)

1. Start ChatFilter: `chatfilter`
2. Open web interface: `http://127.0.0.1:8000`
3. Navigate to **Proxies** in the navigation menu
4. Click **Add Proxy** and configure:
   - **Name:** A friendly name for the proxy (e.g., "Office Proxy")
   - **Type:** SOCKS5 or HTTP
   - **Host:** Proxy server hostname/IP
   - **Port:** Proxy server port (default: 1080 for SOCKS5, 8080 for HTTP)
   - **Username/Password:** If proxy requires authentication
5. Click **Save** to add the proxy
6. Assign the proxy to your session(s) on the Sessions page

**Features:**
- Multiple proxies can be configured and managed
- Health monitoring automatically disables failing proxies
- Proxies can be retested and re-enabled after fixing issues

#### Method 3: Programmatic Configuration

```python
from pathlib import Path
from chatfilter.telegram.client import TelegramClientLoader
from chatfilter.config import ProxyConfig, ProxyType

# Configure proxy
proxy = ProxyConfig(
    enabled=True,
    proxy_type=ProxyType.SOCKS5,
    host="proxy.example.com",
    port=1080,
    username="user",  # Optional
    password="pass",  # Optional
)

# Create client with proxy
loader = TelegramClientLoader(
    session_path=Path("sessions/my_session/session.session"),
    use_secure_storage=True,
)

async with loader.create_client(proxy=proxy) as client:
    me = await client.get_me()
    print(f"Connected via proxy: {me.username}")
```

### Using Corporate Proxy

If your organization requires using a corporate proxy:

1. **Get proxy details from IT:**
   - Proxy hostname/IP
   - Proxy port
   - Proxy type (SOCKS5 or HTTP)
   - Authentication credentials (if required)

2. **Configure ChatFilter:**
   - Open the web interface and navigate to **Proxies**
   - Click **Add Proxy** and enter the details provided by IT
   - Save the proxy and assign it to your session(s)

3. **Common corporate proxy ports:**
   - HTTP proxy: 8080, 3128, 8888
   - SOCKS5 proxy: 1080, 9050

### Public Proxy Services

For development or personal use, you can use public proxy services:

**SOCKS5 Proxies:**
- SSH tunnel: `ssh -D 1080 user@server.com` (creates local SOCKS5 proxy)
- Cloud VPS with SSH access
- Commercial VPN providers with SOCKS5 support

**HTTP Proxies:**
- Public HTTP proxy lists (use with caution, security concerns)
- Commercial proxy services

**Warning:** Avoid free public proxies for sensitive data. They may log your traffic or inject malicious content.

### Proxy Performance Considerations

**Timeout Settings:**
When using proxies, you may need to increase connection timeouts:

```python
loader.create_client(
    proxy=proxy,
    timeout=60.0,  # Increased from default 30s
    connection_retries=10,  # More retries through proxy
    retry_delay=2,  # Longer delay between retries
)
```

**Environment Variables:**
```bash
export CHATFILTER_CONNECT_TIMEOUT=60
```

## Troubleshooting

### Connection Timeout

**Symptom:** Application fails with "Connection timeout" error

**Possible Causes:**
1. Firewall blocking port 443
2. DNS resolution failing
3. Telegram servers unreachable from your network

**Solutions:**
1. Verify port 443 is allowed: `telnet flora.telegram.org 443`
2. Check DNS resolution: `nslookup flora.telegram.org`
3. Try configuring a proxy
4. Contact your IT team to whitelist Telegram domains

### MTProto Protocol Blocked

**Symptom:** Connection established but immediately drops, or "Protocol error" messages

**Cause:** Deep packet inspection (DPI) blocking MTProto traffic

**Solution:** Configure SOCKS5 proxy to tunnel traffic

### Proxy Connection Failed

**Symptom:** "Failed to connect through proxy" error

**Solutions:**
1. Verify proxy host/port are correct
2. Check proxy requires authentication (add username/password)
3. Try different proxy type (SOCKS5 vs HTTP)
4. Test proxy independently: `curl --proxy socks5://proxy.example.com:1080 https://telegram.org`

### Slow Performance

**Symptom:** Very slow message fetching, frequent timeouts

**Causes:**
1. Slow proxy server
2. Network congestion
3. Proxy server geographically distant

**Solutions:**
1. Use faster proxy server (local or closer geographically)
2. Increase timeout settings
3. Choose proxy server in same region as Telegram data centers

### Certificate Errors

**Symptom:** SSL/TLS certificate verification errors

**Cause:** Corporate firewall performing SSL interception

**Solutions:**
1. Configure system to trust corporate CA certificate
2. Use SOCKS5 proxy that doesn't intercept SSL
3. Contact IT team about SSL interception policy

## Testing Connectivity

### Manual Tests

Test Telegram connectivity from command line:

```bash
# Test HTTPS connectivity to Telegram
curl -I https://flora.telegram.org

# Test specific port
telnet flora.telegram.org 443

# Test through proxy
curl --proxy socks5://proxy.example.com:1080 https://flora.telegram.org
```

### ChatFilter Diagnostic Mode

Run ChatFilter with debug logging to see connection details:

```bash
chatfilter --debug --log-level DEBUG
```

Check log file for connection errors:
```bash
# macOS
tail -f ~/Library/Logs/ChatFilter/chatfilter.log

# Windows
type %LOCALAPPDATA%\ChatFilter\Logs\chatfilter.log

# Linux
tail -f ~/.local/state/chatfilter/log/chatfilter.log
```

## Best Practices

### For Developers

1. **Test without proxy first:** Verify basic connectivity before adding proxy
2. **Use SOCKS5 over HTTP:** Better performance and compatibility
3. **Log connection details:** Enable debug logging during development
4. **Handle timeout gracefully:** Increase timeouts when using proxies

### For System Administrators

1. **Whitelist Telegram domains:** Prefer domain-based rules over IP-based
2. **Allow port 443:** Telegram primarily uses HTTPS port
3. **Document proxy settings:** Maintain internal documentation for users
4. **Monitor connection health:** Use ChatFilter's heartbeat monitoring
5. **Use local proxy:** Deploy local SOCKS5 proxy for better performance

### For End Users

1. **Start without proxy:** Only enable proxy if direct connection fails
2. **Keep credentials secure:** Use secure storage for proxy credentials
3. **Test connectivity:** Use diagnostic mode to verify configuration
4. **Contact IT support:** Get proper proxy details from your IT team

## Security Considerations

### Proxy Security

**Do:**
- Use trusted proxy servers (corporate, personal VPS, reputable VPN)
- Use authentication when available
- Use encrypted connections (SSH tunnels, SOCKS5 over SSH)
- Keep proxy credentials secure (never commit to version control)

**Don't:**
- Use random public proxies for sensitive data
- Share proxy credentials
- Use HTTP proxies without authentication on untrusted networks
- Disable SSL verification

### Firewall Bypass Ethics

**Acceptable Use:**
- Using proxy to access Telegram when corporate policy allows it
- Routing through approved corporate proxy infrastructure
- Personal use on personal devices

**Not Acceptable:**
- Bypassing corporate security policies that explicitly prohibit Telegram
- Unauthorized proxy servers on corporate network
- Violating terms of employment or network usage policies

**Recommendation:** Always get approval from your IT team before deploying ChatFilter in a corporate environment. Provide them with this documentation to help them understand the network requirements.

## Advanced Configuration

### SSH Tunnel as SOCKS5 Proxy

Create a SOCKS5 proxy using SSH:

```bash
# Create local SOCKS5 proxy on port 1080
ssh -D 1080 -N -f user@your-server.com
```

Then configure ChatFilter to use `localhost:1080` as SOCKS5 proxy.

### Multiple Proxy Chains

For highly restricted environments, you can chain proxies:

```bash
# SSH through first proxy to create local SOCKS5
ssh -o ProxyCommand="nc -X connect -x proxy1.com:8080 %h %p" \
    -D 1080 -N -f user@proxy2.com
```

### Docker Container with Proxy

When running ChatFilter in Docker:

```dockerfile
FROM python:3.11
WORKDIR /app
COPY . .
RUN pip install .

# Configure proxy via environment
ENV HTTP_PROXY=http://proxy.example.com:8080
ENV HTTPS_PROXY=http://proxy.example.com:8080

CMD ["chatfilter"]
```

Or use Docker's `--network` option to route through proxy container.

## Additional Resources

- [Telegram API Documentation](https://core.telegram.org/api)
- [MTProto Protocol](https://core.telegram.org/mtproto)
- [Telegram Server Status](https://t.me/ISCstatus)
- [ChatFilter Documentation](../README.md)

## Support

If you encounter network connectivity issues:

1. Check this documentation first
2. Enable debug logging: `chatfilter --debug`
3. Review log files for specific errors
4. Try proxy configuration
5. Contact your IT team for firewall assistance
6. Open an issue on GitHub with debug logs (redact sensitive info)
