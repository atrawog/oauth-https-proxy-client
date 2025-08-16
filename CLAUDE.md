# OAuth HTTPS Proxy Client Documentation

## Overview

The `oauth-https-proxy-client` is a Python CLI tool that provides enhanced interaction with the proxy system. It features intelligent table formatting, context-aware data display, and comprehensive command coverage.

## Installation

```bash
# Install via pixi (recommended)
pixi install

# Or install directly
pip install -e ./oauth-https-proxy-client
```

## Features

- **Enhanced Table Formatting**: Smart type detection with contextual column layouts
- **Visual Status Indicators**: Color-coded statuses with icons (● active, ◌ pending, ✗ error)
- **Relative Time Display**: Shows "5m ago" instead of timestamps for recent events
- **Smart Data Summaries**: Complex objects shown with meaningful summaries
- **Empty State Messages**: Helpful commands shown when no data exists
- **Multiple Output Formats**: JSON, YAML, CSV, and enhanced tables
- **Alternating Row Colors**: Improved readability with subtle row striping
- **Context-Aware Columns**: Different layouts for tokens, proxies, services, routes, logs
- **HTTP Status Coloring**: 2xx green, 3xx yellow, 4xx red, 5xx bold red
- **Port Mapping Display**: Clear visualization of port mappings (3000→80)
- **Resource Summaries**: CPU/memory limits shown concisely (512m/1cpu)

## Configuration

The client can be configured via:
- **Environment Variables**: `TOKEN`, `ADMIN_TOKEN`, `API_URL`
- **Command Line Options**: `--token`, `--base-url`, `--format`
- **Configuration File**: `~/.config/proxy-client/config.yml`

### Configuration File Example

```yaml
# ~/.config/proxy-client/config.yml
api_url: http://localhost:9000
token: acm_your_token_here
format: table
```

## Enhanced Display Examples

### Token List Display
```
┌──────────────┬──────────────────────┬──────────┬────────┐
│ Token Name   │ Certificate Email    │ Created  │ Owner  │
├──────────────┼──────────────────────┼──────────┼────────┤
│ admin        │ admin@example.com    │ 2d ago   │ —      │
│ developer    │ dev@example.com      │ 5h ago   │ admin  │
└──────────────┴──────────────────────┴──────────┴────────┘
```

### Proxy Status Display
```
┌─────────────────┬──────────────────┬──────────────┬──────┬──────────────┐
│ Hostname        │ Target           │ Status       │ Auth │ Certificate  │
├─────────────────┼──────────────────┼──────────────┼──────┼──────────────┤
│ api.example.com │ backend:3000     │ HTTP | HTTPS✓│ ✓    │ api-cert     │
│ app.example.com │ localhost:8080   │ HTTP | HTTPS⚠│ ✗    │ —            │
└─────────────────┴──────────────────┴──────────────┴──────┴──────────────┘
Summary: 2 proxies | 1 HTTPS | 1 with auth
```

### Service Display with Ports
```
┌─────────────┬──────────┬──────────┬─────────────┬───────────┐
│ Service     │ Type     │ Status   │ Ports       │ Resources │
├─────────────┼──────────┼──────────┼─────────────┼───────────┤
│ my-app      │ docker   │ ● running│ 3000→80     │ 512m/1cpu │
│ redis       │ docker   │ ● running│ 6379→6379   │ 256m/0.5cpu│
│ api-gateway │ external │ ● active │ —           │ —         │
└─────────────┴──────────┴──────────┴─────────────┴───────────┘
Summary: 2 Docker | 1 External
```

## Enhanced Table Formatter Architecture

The client includes an intelligent table formatting system that automatically detects data types and applies appropriate formatting.

### Type Detection
The formatter automatically detects these data types:
- **tokens**: Detected by presence of `token` or `cert_email` fields
- **certificates**: Detected by `cert_name` or `fullchain_pem` fields  
- **proxies**: Detected by `hostname` and `target_url` fields
- **services**: Detected by `service_name` or `image` fields
- **routes**: Detected by `route_id` or `path_pattern` fields
- **oauth_clients**: Detected by `client_id` and `client_secret` fields
- **logs**: Detected by `client_ip` or `request_path` fields

### Column Configurations
Each data type has custom column configurations:
```python
{
  'columns': ['name', 'status', 'created_at'],  # Fields to display
  'headers': ['Name', 'Status', 'Created'],      # Column headers
  'styles': ['bold cyan', 'status', 'date'],     # Formatting styles
  'box': ROUNDED,                                # Table border style
}
```

### Smart Formatting Styles
- **status**: Color-coded with icons (● green, ◌ yellow, ✗ red)
- **date**: Relative time for recent dates (5m ago, 2h ago, 3d ago)
- **bool**: Checkmarks ✓ or crosses ✗ with colors
- **number**: K/M suffixes for large numbers
- **status_code**: HTTP status code coloring
- **mono**: Monospace font for IDs and tokens

## Command Structure

### Basic Usage
```bash
proxy-client [OPTIONS] COMMAND [ARGS]...
```

### Global Options
- `--token TEXT` - Authentication token
- `--base-url TEXT` - API base URL
- `--format [table|json|yaml|csv]` - Output format
- `--help` - Show help message

## Available Commands

### Token Management
```bash
proxy-client token list
proxy-client token create <name> [--email EMAIL]
proxy-client token show <name>
proxy-client token delete <name>
proxy-client token update-email <email>
```

### Certificate Management
```bash
proxy-client cert list
proxy-client cert create <name> <domain> [--staging]
proxy-client cert show <name> [--pem]
proxy-client cert delete <name>
proxy-client cert renew <name>
```

### Proxy Management
```bash
proxy-client proxy list
proxy-client proxy create <hostname> <target-url>
proxy-client proxy show <hostname>
proxy-client proxy delete <hostname>
proxy-client proxy auth-enable <hostname>
proxy-client proxy auth-config <hostname> --users "alice,bob"
```

### Service Management
```bash
proxy-client service list [--type docker|external]
proxy-client service create <name> <image>
proxy-client service show <name>
proxy-client service delete <name>
proxy-client service logs <name> [--lines 100]
proxy-client service stats <name>
```

### Route Management
```bash
proxy-client route list
proxy-client route create <path> <target-type> <target-value>
proxy-client route show <route-id>
proxy-client route delete <route-id>
proxy-client route list-by-scope [global|proxy]
```

### Log Queries
```bash
proxy-client log search [--query "status:500"] [--hours 24]
proxy-client log errors [--hours 1]
proxy-client log by-ip <ip> [--hours 24]
proxy-client log by-host <fqdn> [--hours 24]  # Query by client FQDN (reverse DNS)
proxy-client log by-proxy <hostname> [--hours 24]  # Query by proxy hostname
proxy-client log stats [--hours 24]
```

### OAuth Management
```bash
proxy-client oauth clients [--active-only]
proxy-client oauth sessions
proxy-client oauth status
```

## Usage Examples

### Use with Environment Variable
```bash
export TOKEN=acm_your_token_here
proxy-client token list
```

### Use with Command Line Option
```bash
proxy-client --token acm_your_token_here proxy list
```

### Different Output Formats
```bash
proxy-client --format json service list
proxy-client --format yaml cert list
proxy-client --format csv route list
```

### Interactive Commands with Prompts
```bash
proxy-client proxy create api.example.com http://backend:3000
proxy-client service create my-app nginx:latest --port 80
```

### Advanced Filtering and Searching
```bash
proxy-client log search --query "status:500" --hours 24
proxy-client service list --type docker
proxy-client route list-by-scope proxy
```

## Empty State Handling

When no data exists, helpful commands are shown:
```
No tokens found. Create one with:
  proxy-client token create <name> --email <email>
```

## Error Handling

The client provides clear error messages:
```
Error: Authentication failed
Please check your token with: proxy-client token info
```

## Shell Completion

Enable shell completion for bash/zsh:
```bash
# Bash
eval "$(_PROXY_CLIENT_COMPLETE=bash_source proxy-client)"

# Zsh
eval "$(_PROXY_CLIENT_COMPLETE=zsh_source proxy-client)"
```

## Scripting Support

The client supports scripting with JSON output:
```bash
# Get all proxy hostnames
proxy-client --format json proxy list | jq -r '.[].hostname'

# Check if service exists
proxy-client --format json service show my-app > /dev/null 2>&1 && echo "exists"
```

## Plugin Architecture

The client uses a modular command structure:
```
commands/
├── tokens.py       # Token commands
├── certificates.py # Certificate commands
├── proxies.py      # Proxy commands
├── services.py     # Service commands
├── routes.py       # Route commands
├── logs.py         # Log commands
└── oauth.py        # OAuth commands
```

## Formatters

Multiple output formatters are available:
```
formatters/
├── base.py           # Base formatter interface
├── enhanced_table.py # Smart table formatting
├── json_formatter.py # JSON output
├── yaml_formatter.py # YAML output
└── csv_formatter.py  # CSV output
```

## Best Practices

1. **Use Environment Variables**: Set `TOKEN` to avoid repetition
2. **Choose Appropriate Format**: Use `table` for humans, `json` for scripts
3. **Leverage Filtering**: Use built-in filters to reduce output
4. **Monitor with Follow**: Use `--follow` for real-time monitoring
5. **Script with JSON**: Parse JSON output for automation

## Troubleshooting

### Connection Issues
```bash
# Check API connectivity
proxy-client --base-url http://localhost:9000 token info
```

### Authentication Issues
```bash
# Verify token
proxy-client token info
```

### Format Issues
```bash
# Force specific format
proxy-client --format json proxy list
```

## Related Documentation

- [API Documentation](../src/api/CLAUDE.md) - API endpoints
- [Main Documentation](../CLAUDE.md) - System overview
- [Just Commands](../justfile.md) - Alternative CLI interface