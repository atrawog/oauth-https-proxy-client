"""Enhanced table formatter with context-aware formatting."""

from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from io import StringIO
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED, MINIMAL, SIMPLE, SIMPLE_HEAD
import json


class EnhancedTableFormatter:
    """Smart table formatter with type-specific layouts."""
    
    # Column configurations for different data types
    COLUMN_CONFIGS = {
        'tokens': {
            'columns': ['name', 'cert_email', 'created_at', 'owner'],
            'headers': ['Token Name', 'Certificate Email', 'Created', 'Owner'],
            'styles': ['bold cyan', 'yellow', 'dim', 'dim'],
            'box': ROUNDED,
        },
        'certificates': {
            'columns': ['cert_name', 'domains', 'status', 'expires_at', 'email'],
            'headers': ['Certificate', 'Domains', 'Status', 'Expires', 'Email'],
            'styles': ['bold cyan', 'white', 'status', 'date', 'dim'],
            'box': ROUNDED,
        },
        'proxies': {
            'columns': ['hostname', 'target_url', 'status_summary', 'auth_enabled', 'cert_name'],
            'headers': ['Hostname', 'Target', 'Status', 'Auth', 'Certificate'],
            'styles': ['bold cyan', 'blue', 'status', 'bool', 'yellow'],
            'box': ROUNDED,
        },
        'services': {
            'columns': ['service_name', 'service_type', 'status_info', 'ports_summary', 'memory_cpu'],
            'headers': ['Service', 'Type', 'Status', 'Ports', 'Resources'],
            'styles': ['bold cyan', 'yellow', 'status', 'dim', 'dim'],
            'box': ROUNDED,
        },
        'routes': {
            'columns': ['route_id', 'path_pattern', 'target_summary', 'priority', 'scope_display', 'enabled'],
            'headers': ['ID', 'Path', 'Target', 'Priority', 'Proxy/Scope', 'Status'],
            'styles': ['dim', 'bold cyan', 'blue', 'number', 'yellow', 'bool'],
            'box': SIMPLE,
        },
        'oauth_clients': {
            'columns': ['client_id', 'client_name', 'token_count', 'usage_count', 'last_used', 'created_at'],
            'headers': ['Client ID', 'Name', 'Tokens', 'Uses', 'Last Used', 'Created'],
            'styles': ['mono', 'bold cyan', 'number', 'number', 'date', 'date'],
            'box': ROUNDED,
        },
        'oauth_tokens': {
            'columns': ['jti', 'token_type', 'username', 'client_name', 'usage_count', 'last_used', 'time_remaining', 'issued_at'],
            'headers': ['Token ID', 'Type', 'User', 'Client', 'Uses', 'Last Used', 'Expires', 'Issued'],
            'styles': ['mono', 'dim', 'bold cyan', 'yellow', 'number', 'date', 'status', 'date'],
            'box': ROUNDED,
        },
        'logs': {
            'columns': [
                'timestamp', 
                'status_code', 
                'method', 
                'path', 
                'response_time_ms',
                'client_ip',
                'client_hostname',
                'proxy_hostname',
                'user_id',
                'auth_type',
                'query',
                'error'
            ],
            'headers': [
                'Time',
                'Status',
                'Method',
                'Path',
                'ms',
                'Client IP',
                'Client Host',
                'Proxy',
                'User',
                'Auth',
                'Query',
                'Error'
            ],
            'styles': [
                'date',          # timestamp
                'status_code',   # status_code
                None,           # method
                None,           # path
                'number',       # response_time_ms
                'yellow',       # client_ip
                'dim',          # client_hostname
                'cyan',         # proxy_hostname
                None,           # user_id
                'dim',          # auth_type
                'dim',          # query
                'red'           # error
            ],
            'box': SIMPLE_HEAD,
        }
    }
    
    def __init__(self):
        """Initialize the formatter."""
        self.console = Console()
    
    def format(self, data: Any, data_type: Optional[str] = None, **kwargs) -> str:
        """Format data with smart type detection and layout.
        
        Args:
            data: Data to format
            data_type: Type hint for data ('tokens', 'certificates', etc.)
            **kwargs: Additional formatting options
            
        Returns:
            Formatted table string
        """
        # Handle empty data
        if not data:
            return self._empty_message(data_type)
        
        # Handle nested response formats like {'total': n, 'logs': [...]} or {'services': [...]}
        if isinstance(data, dict):
            # Handle log response format
            if 'logs' in data:
                logs_data = data['logs']
                if data_type == 'logs' or (not data_type and logs_data and self._detect_data_type(logs_data[0]) == 'logs'):
                    return self._format_logs_multiline(logs_data, **kwargs)
                data = logs_data
            # Handle service response format
            elif 'services' in data and isinstance(data['services'], list):
                services_data = data['services']
                # Check if empty
                if not services_data:
                    return self._empty_message('services')
                data = services_data
                if not data_type:
                    data_type = 'services'
            # Handle other nested list responses
            elif 'items' in data and isinstance(data['items'], list):
                data = data['items']
            elif 'results' in data and isinstance(data['results'], list):
                data = data['results']
        
        # Convert single item to list
        if isinstance(data, dict) and not self._is_key_value_dict(data):
            data = [data]
        
        # Auto-detect data type if not provided
        if not data_type and isinstance(data, list) and data:
            data_type = self._detect_data_type(data[0])
        
        # Special multi-line format for logs
        if data_type == 'logs':
            return self._format_logs_multiline(data, **kwargs)
        
        # Prepare data for display
        prepared_data = self._prepare_data(data, data_type)
        
        # Get configuration
        config = self.COLUMN_CONFIGS.get(data_type, self._default_config())
        
        # Create and populate table
        table = self._create_table(prepared_data, config, **kwargs)
        
        # Render to string
        self.console.file = StringIO()
        self.console.print(table)
        output = self.console.file.getvalue()
        
        # Add summary if applicable
        if data_type and len(data) > 5:
            summary = self._generate_summary(data, data_type)
            if summary:
                output += f"\n{summary}"
        
        return output
    
    def _detect_data_type(self, sample: Dict) -> Optional[str]:
        """Auto-detect data type from sample record."""
        if 'token' in sample or 'cert_email' in sample:
            return 'tokens'
        elif 'cert_name' in sample or 'fullchain_pem' in sample:
            return 'certificates'
        elif 'hostname' in sample and 'target_url' in sample:
            return 'proxies'
        elif 'service_name' in sample or 'image' in sample:
            return 'services'
        elif 'route_id' in sample or 'path_pattern' in sample:
            return 'routes'
        elif 'jti' in sample and 'token_type' in sample:
            return 'oauth_tokens'
        elif 'client_id' in sample and ('client_secret' in sample or 'client_name' in sample):
            return 'oauth_clients'
        elif 'client_ip' in sample or 'proxy_hostname' in sample or 'response_time_ms' in sample:
            return 'logs'
        return None
    
    def _prepare_data(self, data: List[Dict], data_type: Optional[str]) -> List[Dict]:
        """Prepare and enhance data for display."""
        if not data_type:
            return data
        
        prepared = []
        for item in data:
            enhanced = item.copy()
            
            # Add computed fields based on type
            if data_type == 'proxies':
                enhanced['status_summary'] = self._proxy_status(item)
            elif data_type == 'services':
                enhanced['status_info'] = self._service_status(item)
                enhanced['ports_summary'] = self._ports_summary(item)
                enhanced['memory_cpu'] = self._resource_summary(item)
            elif data_type == 'routes':
                enhanced['target_summary'] = self._route_target(item)
                enhanced['scope_display'] = self._route_scope(item)
            elif data_type == 'logs':
                # All fields are already present, no special processing needed
                pass
            elif data_type == 'oauth_clients':
                # token_count is already provided by the API
                pass
            
            prepared.append(enhanced)
        
        return prepared
    
    def _create_table(self, data: List[Dict], config: Dict, **kwargs) -> Table:
        """Create and populate a rich table."""
        # Create table with configuration
        table = Table(
            title=kwargs.get('title'),
            box=config.get('box', ROUNDED),
            show_header=kwargs.get('show_header', True),
            highlight=True,
            row_styles=["none", "dim"],  # Alternating row colors
        )
        
        # Add columns
        columns = config.get('columns', [])
        headers = config.get('headers', columns)
        styles = config.get('styles', [])
        
        for i, (col, header) in enumerate(zip(columns, headers)):
            style = styles[i] if i < len(styles) else None
            # Special handling for client_id column to show full ID
            if col == 'client_id':
                table.add_column(header, style=style if style not in ['status', 'bool', 'date', 'number', 'status_code', 'mono'] else None, 
                                no_wrap=True, min_width=29)
            else:
                table.add_column(header, style=style if style not in ['status', 'bool', 'date', 'number', 'status_code', 'mono'] else None)
        
        # Add rows
        for item in data:
            row = []
            for i, col in enumerate(columns):
                value = item.get(col, '')
                style = styles[i] if i < len(styles) else None
                formatted = self._format_cell(value, style, column_name=col)
                row.append(formatted)
            table.add_row(*row)
        
        return table
    
    def _format_cell(self, value: Any, style: Optional[str], column_name: Optional[str] = None) -> str:
        """Format individual cell based on style hint."""
        if value is None or value == '':
            return Text("—", style="dim")
        
        # Handle style-specific formatting
        if style == 'status':
            return self._format_status(value)
        elif style == 'bool':
            return Text("✓", style="green") if value else Text("✗", style="dim red")
        elif style == 'date':
            return self._format_date(value)
        elif style == 'number':
            return self._format_number(value)
        elif style == 'status_code':
            return self._format_status_code(value)
        elif style == 'mono':
            # Don't truncate client_id values
            return Text(str(value), style="bold mono", no_wrap=False)
        
        # Handle complex types
        if isinstance(value, list):
            if not value:
                return Text("[]", style="dim")
            if len(value) == 1:
                return str(value[0])
            return f"{value[0]} (+{len(value)-1})"
        elif isinstance(value, dict):
            return Text(f"{{{len(value)} fields}}", style="dim")
        
        # Default string formatting
        text = str(value)
        # Don't truncate client_id values
        if column_name != 'client_id' and len(text) > 50:
            text = text[:47] + "..."
        return text
    
    def _format_status(self, status: str) -> Text:
        """Format status with color coding."""
        status_lower = str(status).lower()
        
        # Handle token expiration times
        if 'expired' in status_lower:
            return Text("expired", style="red")
        elif status_lower.endswith('m'):  # Minutes remaining
            try:
                minutes = int(status_lower[:-1])
                if minutes <= 5:
                    return Text(status, style="bold red")
                elif minutes <= 30:
                    return Text(status, style="yellow")
                else:
                    return Text(status, style="green")
            except:
                pass
        elif status_lower.endswith('h'):  # Hours remaining
            return Text(status, style="green")
        elif status_lower.endswith('d'):  # Days remaining
            return Text(status, style="green")
        
        # Handle regular statuses
        elif 'active' in status_lower or 'running' in status_lower or 'ready' in status_lower:
            return Text(f"● {status}", style="green")
        elif 'pending' in status_lower or 'starting' in status_lower:
            return Text(f"◌ {status}", style="yellow")
        elif 'error' in status_lower or 'failed' in status_lower:
            return Text(f"✗ {status}", style="red")
        elif 'stopped' in status_lower or 'disabled' in status_lower:
            return Text(f"○ {status}", style="dim")
        else:
            return Text(status)
    
    def _format_date(self, value: Any) -> Text:
        """Format date/time values."""
        if not value:
            return Text("never", style="dim")
        
        try:
            # Parse ISO format
            if isinstance(value, str):
                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                # Format as relative time if recent
                now = datetime.now(dt.tzinfo)
                diff = now - dt
                if diff.days == 0 and diff.seconds < 3600:
                    mins = diff.seconds // 60
                    return Text(f"{mins}m ago", style="yellow")
                elif diff.days == 0:
                    hours = diff.seconds // 3600
                    return Text(f"{hours}h ago", style="yellow")
                elif diff.days < 7:
                    return Text(f"{diff.days}d ago", style="dim")
                else:
                    return Text(dt.strftime("%Y-%m-%d"), style="dim")
        except:
            pass
        
        return Text(str(value)[:10], style="dim")
    
    def _format_number(self, value: Any) -> Text:
        """Format numeric values."""
        try:
            num = float(value)
            if num >= 1000000:
                return Text(f"{num/1000000:.1f}M", style="bold")
            elif num >= 1000:
                return Text(f"{num/1000:.1f}K", style="bold")
            else:
                return Text(str(int(num)), style="cyan")
        except:
            return Text(str(value))
    
    def _format_status_code(self, code: Any) -> Text:
        """Format HTTP status codes with color."""
        try:
            code = int(code)
            if 200 <= code < 300:
                return Text(str(code), style="green")
            elif 300 <= code < 400:
                return Text(str(code), style="yellow")
            elif 400 <= code < 500:
                return Text(str(code), style="red")
            elif code >= 500:
                return Text(str(code), style="bold red")
            else:
                return Text(str(code))
        except:
            return Text(str(code))
    
    def _proxy_status(self, proxy: Dict) -> str:
        """Generate proxy status summary."""
        statuses = []
        if proxy.get('enable_http'):
            statuses.append('HTTP')
        if proxy.get('enable_https'):
            if proxy.get('cert_name'):
                statuses.append('HTTPS✓')
            else:
                statuses.append('HTTPS⚠')
        if proxy.get('auth_enabled'):
            statuses.append('Auth')
        return ' | '.join(statuses) if statuses else 'Disabled'
    
    def _service_status(self, service: Dict) -> str:
        """Generate service status summary."""
        status = service.get('status', 'unknown')
        if service.get('service_type') == 'docker':
            container_status = service.get('container_status', '')
            if container_status:
                return container_status
        return status
    
    def _ports_summary(self, service: Dict) -> str:
        """Generate ports summary for service."""
        ports = service.get('port_configs', [])
        if not ports:
            if service.get('internal_port'):
                return str(service['internal_port'])
            return '—'
        
        port_strs = []
        for p in ports[:2]:  # Show max 2 ports
            host = p.get('host', p.get('external_port'))
            container = p.get('container', p.get('internal_port'))
            if host and container:
                port_strs.append(f"{host}→{container}")
        
        if len(ports) > 2:
            port_strs.append(f"+{len(ports)-2}")
        
        return ', '.join(port_strs) if port_strs else '—'
    
    def _resource_summary(self, service: Dict) -> str:
        """Generate resource summary for service."""
        parts = []
        if service.get('memory_limit'):
            parts.append(service['memory_limit'])
        if service.get('cpu_limit'):
            parts.append(f"{service['cpu_limit']}cpu")
        return ' / '.join(parts) if parts else '—'
    
    def _route_target(self, route: Dict) -> str:
        """Generate route target summary."""
        target_type = route.get('target_type', '')
        target_value = route.get('target_value', '')
        
        if target_type == 'port':
            return f":{target_value}"
        elif target_type == 'service':
            return f"→{target_value}"
        elif target_type == 'hostname':
            return f"@{target_value}"
        elif target_type == 'url':
            return f"↗{target_value[:30]}"
        return target_value
    
    def _route_scope(self, route: Dict) -> str:
        """Generate route scope display with proxy hostnames."""
        scope = route.get('scope', 'global')
        if scope == 'global':
            return 'global'
        elif scope == 'proxy':
            proxies = route.get('proxy_hostnames', [])
            if not proxies:
                return 'proxy (none)'
            elif len(proxies) == 1:
                return f"{proxies[0]}"
            elif len(proxies) <= 2:
                return f"{proxies[0]}, {proxies[1]}"
            else:
                return f"{proxies[0]} (+{len(proxies)-1})"
        return scope
    
    def _generate_summary(self, data: List[Dict], data_type: str) -> str:
        """Generate summary statistics for data."""
        if data_type == 'proxies':
            https_count = sum(1 for p in data if p.get('enable_https'))
            auth_count = sum(1 for p in data if p.get('auth_enabled'))
            return f"Summary: {len(data)} proxies | {https_count} HTTPS | {auth_count} with auth"
        
        elif data_type == 'services':
            docker_count = sum(1 for s in data if s.get('service_type') == 'docker')
            external_count = sum(1 for s in data if s.get('service_type') == 'external')
            return f"Summary: {docker_count} Docker | {external_count} External"
        
        elif data_type == 'routes':
            global_count = sum(1 for r in data if r.get('scope') == 'global')
            proxy_count = sum(1 for r in data if r.get('scope') == 'proxy')
            return f"Summary: {global_count} global | {proxy_count} proxy-specific"
        
        return ""
    
    def _empty_message(self, data_type: Optional[str]) -> str:
        """Generate empty data message."""
        if data_type == 'tokens':
            return "No tokens found. Create one with: proxy-client token create <name>"
        elif data_type == 'certificates':
            return "No certificates found. Create one with: proxy-client cert create <name> <domain>"
        elif data_type == 'proxies':
            return "No proxies configured. Create one with: proxy-client proxy create <hostname> <target>"
        elif data_type == 'services':
            return "No services running. Create one with: proxy-client service create <name> <image>"
        elif data_type == 'routes':
            return "No routes configured. Create one with: proxy-client route create <path> <type> <target>"
        return "No data to display"
    
    def _default_config(self) -> Dict:
        """Default configuration for unknown data types."""
        return {
            'columns': [],
            'headers': [],
            'styles': [],
            'box': SIMPLE,
        }
    
    def _is_key_value_dict(self, data: Dict) -> bool:
        """Check if dict should be displayed as key-value pairs."""
        # If all values are simple types, treat as key-value
        for value in data.values():
            if isinstance(value, (list, dict)) and value:
                return False
        return True
    
    def _format_logs_multiline(self, logs: List[Dict], show_summary: bool = True, **kwargs) -> str:
        """Format logs in a comprehensive multi-line format showing ALL fields.
        
        Args:
            logs: List of log entries
            **kwargs: Additional formatting options
            
        Returns:
            Formatted multi-line log output
        """
        if not logs:
            return "No logs found"
        
        output = []
        # Only show header for summary view
        if show_summary:
            output.append("=" * 90)
            output.append(f"System Logs (Last {kwargs.get('hours', 1)} hour)")
            output.append("=" * 90)
            output.append("")
        
        # Process each log entry
        for log in logs:
            # Parse status for color coding
            status = log.get('status_code', 0)
            if status >= 500:
                status_marker = "[red]✗[/red]"
            elif status >= 400:
                status_marker = "[yellow]⚠[/yellow]"
            elif status >= 300:
                status_marker = "[blue]→[/blue]"
            elif status >= 200:
                status_marker = "[green]✓[/green]"
            else:
                status_marker = "[dim]○[/dim]"
            
            # Line 1: Timestamp, status, method, path, response time
            timestamp = log.get('timestamp', 'N/A')
            if timestamp != 'N/A':
                # Format timestamp more readably
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass
            
            method = log.get('method', 'N/A')
            path = log.get('path', '/')
            response_time = log.get('response_time_ms', 0)
            
            output.append(f"[{timestamp}] {status_marker} {status} {method} {path} ({response_time:.0f}ms)")
            
            # Line 2: Client and proxy info
            client_ip = log.get('client_ip', 'unknown')
            client_hostname = log.get('client_hostname', '')
            proxy_hostname = log.get('proxy_hostname', 'unknown')
            
            if client_hostname and client_hostname != client_ip:
                output.append(f"  Client: {client_ip} ({client_hostname}) → Proxy: {proxy_hostname}")
            else:
                output.append(f"  Client: {client_ip} → Proxy: {proxy_hostname}")
            
            # Line 3: User and auth info
            user_id = log.get('user_id', '')
            auth_type = log.get('auth_type', '')
            if user_id or auth_type:
                output.append(f"  User: {user_id or 'anonymous'} | Auth: {auth_type or 'none'}")
            
            # Line 4: Query parameters
            query = log.get('query', '')
            if query:
                output.append(f"  Query: {query}")
            
            # Line 5: OAuth info
            oauth_client = log.get('oauth_client_id', '')
            oauth_user = log.get('oauth_username', '')
            if oauth_client or oauth_user:
                output.append(f"  OAuth: client={oauth_client or 'N/A'} user={oauth_user or 'N/A'}")
            
            # Line 6: User agent
            user_agent = log.get('user_agent', '')
            if user_agent:
                # Truncate long user agents
                if len(user_agent) > 80:
                    user_agent = user_agent[:77] + "..."
                output.append(f"  UA: {user_agent}")
            
            # Line 7: Referrer
            referrer = log.get('referrer', '')
            if referrer:
                output.append(f"  Referrer: {referrer}")
            
            # Line 8: Bytes sent
            bytes_sent = log.get('bytes_sent', 0)
            if bytes_sent > 0:
                output.append(f"  Bytes: {bytes_sent:,}")
            
            # Line 9: Error message
            error = log.get('error', '')
            if error:
                output.append(f"  [red]ERROR: {error}[/red]")
            
            output.append("")  # Empty line between entries
        
        # Summary statistics (optional)
        if show_summary:
            # Add summary statistics
            output.append("-" * 90)
            output.append("Summary:")
            
            total = len(logs)
            errors = sum(1 for log in logs if log.get('status_code', 0) >= 400)
            avg_time = sum(log.get('response_time_ms', 0) for log in logs) / total if total > 0 else 0
            
            # Count unique values
            unique_ips = len(set(log.get('client_ip', '') for log in logs if log.get('client_ip')))
            unique_users = len(set(log.get('user_id', '') for log in logs if log.get('user_id')))
            auth_types = {}
            for log in logs:
                auth = log.get('auth_type', 'none') or 'none'
                auth_types[auth] = auth_types.get(auth, 0) + 1
            output.append(f"- Total: {total} requests")
            if errors > 0:
                error_pct = (errors / total * 100) if total > 0 else 0
                output.append(f"- Errors: {errors} ({error_pct:.1f}%)")
            output.append(f"- Avg Time: {avg_time:.1f}ms")
            output.append(f"- Unique IPs: {unique_ips}")
            if unique_users > 0:
                output.append(f"- Unique Users: {unique_users}")
            if auth_types:
                auth_str = ", ".join(f"{k}({v})" for k, v in auth_types.items())
                output.append(f"- Auth Types: {auth_str}")
            
            output.append("-" * 90)
        
        # Return the lines as a single string for the caller to print
        # Don't add ANSI codes here - let the caller's console handle formatting
        return "\n".join(output)