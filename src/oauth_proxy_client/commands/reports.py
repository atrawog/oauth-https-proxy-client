"""Connection report generation commands."""

import click
import yaml
import json
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.syntax import Syntax

console = Console()


class SecretMasker:
    """Utility class to mask sensitive data in reports."""
    
    # Patterns for detecting and masking secrets
    SECRET_PATTERNS = {
        'github_client_id': (r'^(Ov23[a-zA-Z0-9]{2}).*([a-zA-Z0-9]{6})$', '{0}...{1}'),
        'jwt': (r'^(eyJ).*([a-zA-Z0-9._-]{4})$', '{0}...{1}'),
        'bearer_token': (r'^(Bearer\s+eyJ).*([a-zA-Z0-9._-]{4})$', '{0}...{1}'),
        'refresh_token': (r'^(ghr_[a-zA-Z0-9]{3}).*([a-zA-Z0-9]{6})$', '{0}...{1}'),
        'device_code': (r'^(dev_[a-zA-Z0-9]{3}).*([a-zA-Z0-9]{2})$', '{0}...{1}'),
        'authorization_code': (r'^(code_[a-zA-Z0-9]{4}).*([a-zA-Z0-9]{2})$', '{0}...{1}'),
        'session_id': (r'^(sess_[a-zA-Z0-9]{3}).*([a-zA-Z0-9]{3})$', '{0}...{1}'),
        'jti': (r'^(jti_[a-zA-Z0-9]{3}).*([a-zA-Z0-9]{2})$', '{0}...{1}'),
        'state': (r'^(state_[a-zA-Z0-9]{2}).*([a-zA-Z0-9])$', '{0}...{1}'),
        'client_id': (r'^(oauth_[a-zA-Z0-9]{2}).*([a-zA-Z0-9]{3})$', '{0}...{1}'),
    }
    
    # Fields that should be completely redacted
    REDACT_FIELDS = {
        'github_client_secret',
        'client_secret',
        'oauth_jwt_private_key',
        'jwt_private_key',
        'private_key',
        'private_key_pem',
        'redis_password',
        'password',
        'secret',
        'api_key',
        'access_key',
        'secret_key',
    }
    
    # Fields that should show presence but not value
    PRESENCE_ONLY_FIELDS = {
        'cookie',
        'set-cookie',
        'set_cookie',
        'x-csrf-token',
        'x_csrf_token',
        'csrf_token',
    }
    
    @classmethod
    def mask_value(cls, field_name: str, value: Any) -> Any:
        """Mask sensitive values based on field name and content."""
        
        if value is None:
            return None
            
        if not isinstance(value, str):
            return value
        
        # Normalize field name for comparison
        field_lower = field_name.lower().replace('-', '_')
        
        # Completely redact certain fields
        if any(secret_field in field_lower for secret_field in cls.REDACT_FIELDS):
            return "[REDACTED]"
        
        # Show presence only for certain fields
        if any(presence_field in field_lower for presence_field in cls.PRESENCE_ONLY_FIELDS):
            return "[PRESENT-BUT-REDACTED]"
        
        # Check for authorization headers
        if field_lower in ['authorization', 'x_authorization']:
            if value.startswith('Bearer '):
                token = value[7:]
                masked = cls.mask_jwt(token)
                return f"Bearer {masked}"
            return "[REDACTED]"
        
        # Apply pattern-based masking
        for pattern_name, (pattern, format_str) in cls.SECRET_PATTERNS.items():
            # Check if field name hints at this pattern type
            if pattern_name.replace('_', '') in field_lower.replace('_', ''):
                match = re.match(pattern, value)
                if match:
                    return format_str.format(*match.groups())
        
        # Generic pattern matching for any field
        for pattern_name, (pattern, format_str) in cls.SECRET_PATTERNS.items():
            match = re.match(pattern, value)
            if match:
                return format_str.format(*match.groups())
        
        # Check if value looks like a secret (high entropy strings)
        if cls.looks_like_secret(value):
            return cls.partial_mask(value)
        
        return value
    
    @staticmethod
    def mask_jwt(token: str) -> str:
        """Mask JWT tokens while preserving structure indicators."""
        parts = token.split('.')
        if len(parts) == 3:  # Valid JWT structure
            # Show beginning of header and end of signature
            return f"{parts[0][:3]}...{parts[2][-4:]}" if len(parts[2]) > 4 else "eyJ...x1dQ"
        return "eyJ...x1dQ"  # Generic masked JWT
    
    @staticmethod
    def partial_mask(value: str, show_start: int = 4, show_end: int = 4) -> str:
        """Partially mask a value, showing only start and end characters."""
        if len(value) <= show_start + show_end + 3:
            return "*" * len(value)
        return f"{value[:show_start]}...{value[-show_end:]}"
    
    @staticmethod
    def looks_like_secret(value: str) -> bool:
        """Heuristic to detect if a string looks like a secret."""
        # Skip URLs, paths, and common non-secret patterns
        if any(prefix in value for prefix in ['http://', 'https://', '/', '.', '@']):
            return False
        
        # Long random-looking strings
        if len(value) > 32 and re.match(r'^[a-zA-Z0-9_\-]+$', value):
            # Check for high entropy (simplified check)
            unique_chars = len(set(value))
            if unique_chars > len(value) * 0.6:  # High entropy
                return True
        
        # Hex strings that look like keys
        if len(value) >= 32 and re.match(r'^[a-f0-9]+$', value, re.IGNORECASE):
            return True
        
        # Base64 strings that look like keys
        if len(value) >= 32 and re.match(r'^[A-Za-z0-9+/]+=*$', value):
            return True
        
        return False
    
    @classmethod
    def mask_dict(cls, data: Dict[str, Any], parent_key: str = '') -> Dict[str, Any]:
        """Recursively mask sensitive values in a dictionary."""
        if data is None:
            return None
            
        masked = {}
        for key, value in data.items():
            current_key = f"{parent_key}.{key}" if parent_key else key
            
            if isinstance(value, dict):
                masked[key] = cls.mask_dict(value, current_key)
            elif isinstance(value, list):
                masked[key] = [
                    cls.mask_dict(item, current_key) if isinstance(item, dict)
                    else cls.mask_value(key, item) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                masked[key] = cls.mask_value(key, value)
        
        return masked


def clean_empty_values(data, aggressive=True):
    """Remove None, empty strings, empty lists, empty dicts, and optionally zeros from nested structure.
    
    Args:
        data: The data structure to clean
        aggressive: If True, removes most zero values and 'null' strings
    
    This function recursively removes empty values. In aggressive mode, it removes:
    - None values
    - Empty strings ('')
    - Empty lists ([])
    - Empty dicts ({})
    - Zero values (0, 0.0) except in very specific cases
    - String 'null'
    - String 'unknown'
    """
    def should_keep_zero(key, value):
        """Determine if a zero value should be kept."""
        if not aggressive:
            # In non-aggressive mode, keep more zeros
            return True
        # Only keep very specific meaningful zeros
        if value == 0:
            # HTTP 2xx status codes start at 200, so 0 might mean SSE/streaming
            if 'status' in key.lower() and 'code' in key.lower():
                return False  # Remove status_code: 0 as it's not meaningful
            # Keep actual port numbers that are explicitly 0
            if key.lower() in ['port', 'http_port', 'https_port']:
                return False  # Remove port 0 as it's not meaningful
            # Keep counts/totals only if they're summary fields
            if key.lower() in ['total_requests', 'total_errors']:
                return True
        if value == 0.0:
            # Remove zero response times - they're likely unset
            if 'response_time' in key.lower():
                return False
            # Remove zero bytes
            if 'bytes' in key.lower():
                return False
        return False
    
    if isinstance(data, dict):
        cleaned = {}
        for key, value in data.items():
            # Recursively clean nested structures
            if isinstance(value, (dict, list)):
                cleaned_value = clean_empty_values(value, aggressive)
                # Only include if not empty after cleaning
                if cleaned_value:  # This will be False for {} and []
                    cleaned[key] = cleaned_value
            # Skip various empty values
            elif value is None or value == '' or value == [] or value == {}:
                continue
            # Skip 'null' and 'unknown' strings if aggressive
            elif aggressive and value in ['null', 'unknown']:
                continue
            # Handle zero values
            elif value == 0 or value == 0.0:
                if should_keep_zero(key, value):
                    cleaned[key] = value
            # Keep all other values
            else:
                cleaned[key] = clean_empty_values(value, aggressive) if isinstance(value, (dict, list)) else value
        return cleaned
    elif isinstance(data, list):
        # Clean list items and remove None/empty elements
        cleaned = []
        for item in data:
            if isinstance(item, (dict, list)):
                cleaned_item = clean_empty_values(item, aggressive)
                if cleaned_item:  # Only add if not empty after cleaning
                    cleaned.append(cleaned_item)
            elif item is not None and item != '' and item != []:
                # Skip 'null' and 'unknown' strings in lists if aggressive
                if not (aggressive and item in ['null', 'unknown', 0, 0.0]):
                    cleaned.append(item)
        return cleaned
    else:
        return data


@click.group('report')
def report_group():
    """Generate comprehensive connection reports."""
    pass


@report_group.command('connection')
@click.argument('ip')
@click.argument('proxy')
@click.option('--hours', type=int, default=24, help='Hours of data to include')
@click.option('--output', '-o', help='Output file (default: stdout)')
@click.option('--format', 'output_format', type=click.Choice(['yaml', 'json']), default='yaml',
              help='Output format')
@click.option('--no-mask', is_flag=True, help='Disable secret masking (DANGEROUS)')
@click.pass_obj
def generate_connection_report(ctx, ip, proxy, hours, output, output_format, no_mask):
    """Generate comprehensive connection report for IP to proxy.
    
    This command collects all available data for connections from a specific IP
    address to a specific proxy hostname, generating a security-hardened report
    suitable for analytics.
    
    Examples:
        proxy-client report connection 34.162.46.92 everything.atratest.org
        proxy-client report connection 10.0.0.1 api.example.com --hours 48 -o report.yaml
    """
    try:
        client = ctx.ensure_client()
        start_time = datetime.now(timezone.utc)
        
        console.print(f"[cyan]Collecting data for {ip} → {proxy} (last {hours} hours)...[/cyan]")
        
        # Initialize report structure
        report = {
            'report': {
                'metadata': {
                    'version': '1.1-secure',
                    'generated_at': start_time.isoformat(),
                    'security_notice': 'Sensitive data has been redacted or masked for security',
                    'query_parameters': {
                        'ip_address': ip,
                        'proxy_hostname': proxy,
                        'time_range_hours': hours,
                        'start_time': (start_time - timedelta(hours=hours)).isoformat(),
                        'end_time': start_time.isoformat()
                    },
                    'data_sources_queried': []
                }
            }
        }
        
        # Collect data using API endpoints
        data_sections = {}
        
        # 1. Get all requests from IP
        console.print("  [dim]• Collecting request logs...[/dim]")
        try:
            ip_logs_response = client.get_sync(f'/logs/ip/{ip}', params={'hours': hours, 'limit': 1000})
            # Filter for the specific proxy
            all_logs = ip_logs_response.get('logs', []) if isinstance(ip_logs_response, dict) else []
            data_sections['requests'] = [log for log in all_logs if log.get('proxy_hostname') == proxy]
            report['report']['metadata']['data_sources_queried'].append('logs:requests')
        except Exception as e:
            console.print(f"    [yellow]⚠ Failed to get request logs: {e}[/yellow]")
            data_sections['requests'] = []
        
        # 2. Get OAuth events for IP
        console.print("  [dim]• Collecting OAuth events...[/dim]")
        oauth_events = []
        
        # Try new structured OAuth events endpoint first (if available)
        # Note: These endpoints may not exist yet - will fall back to legacy
        try:
            # Get OAuth events for this IP
            oauth_ip_response = client.get_sync(f'/oauth/events/ip/{ip}', params={'hours': hours, 'limit': 1000})
            if isinstance(oauth_ip_response, dict) and 'events' in oauth_ip_response:
                oauth_events.extend(oauth_ip_response['events'])
                console.print(f"    [green]✓ Found {len(oauth_ip_response['events'])} events for IP {ip}[/green]")
        except Exception as e:
            # Log the actual error instead of silently passing
            console.print(f"    [yellow]⚠ Failed to get OAuth events for IP {ip}: {e}[/yellow]")
        
        # Also try to get OAuth events for this proxy
        try:
            oauth_proxy_response = client.get_sync(f'/oauth/events/proxy/{proxy}', params={'hours': hours, 'limit': 1000})
            if isinstance(oauth_proxy_response, dict) and 'events' in oauth_proxy_response:
                new_events = 0
                for event in oauth_proxy_response['events']:
                    # Only add if not already present (avoid duplicates)
                    if not any(e.get('timestamp') == event.get('timestamp') and 
                              e.get('event_type') == event.get('event_type') for e in oauth_events):
                        oauth_events.append(event)
                        new_events += 1
                if new_events > 0:
                    console.print(f"    [green]✓ Found {new_events} additional events for proxy {proxy}[/green]")
        except Exception as e:
            console.print(f"    [yellow]⚠ Failed to get OAuth events for proxy {proxy}: {e}[/yellow]")
        
        # Fall back to legacy OAuth logs endpoint if no events found
        if not oauth_events:
            try:
                oauth_response = client.get_sync(f'/logs/oauth/{ip}', params={'hours': hours, 'limit': 1000})
                oauth_events = oauth_response.get('oauth_activity', []) if isinstance(oauth_response, dict) else []
            except Exception as e:
                console.print(f"    [yellow]⚠ Failed to get OAuth events: {e}[/yellow]")
        
        # Sort OAuth events by timestamp
        oauth_events.sort(key=lambda x: x.get('timestamp', 0))
        data_sections['oauth_events'] = oauth_events
        
        if oauth_events:
            console.print(f"    [green]✓ Found {len(oauth_events)} OAuth events[/green]")
            report['report']['metadata']['data_sources_queried'].append('oauth:events')
        else:
            report['report']['metadata']['data_sources_queried'].append('logs:oauth')
        
        # 3. Get proxy configuration
        console.print("  [dim]• Getting proxy configuration...[/dim]")
        try:
            proxy_config = client.get_sync(f'/proxy/targets/{proxy}')
            data_sections['proxy_config'] = proxy_config
            report['report']['metadata']['data_sources_queried'].append('config:proxy')
        except Exception as e:
            console.print(f"    [yellow]⚠ Failed to get proxy config: {e}[/yellow]")
            data_sections['proxy_config'] = {}
        
        # 4. Get OAuth metadata from well-known endpoint
        console.print("  [dim]• Getting OAuth metadata...[/dim]")
        try:
            # Try to get from proxy's well-known endpoint
            oauth_metadata = client.get_sync('/.well-known/oauth-authorization-server')
            data_sections['oauth_server_metadata'] = oauth_metadata
            report['report']['metadata']['data_sources_queried'].append('oauth:metadata')
        except Exception:
            # Construct default metadata
            base_url = f"https://{proxy}"
            data_sections['oauth_server_metadata'] = {
                'issuer': base_url,
                'authorization_endpoint': f"{base_url}/oauth/authorize",
                'token_endpoint': f"{base_url}/oauth/token",
                'jwks_uri': f"{base_url}/oauth/jwks",
            }
        
        # 5. Get applicable routes
        console.print("  [dim]• Getting route configurations...[/dim]")
        try:
            all_routes = client.get_sync('/routes/')
            applicable_routes = []
            for route in all_routes:
                if route.get('scope') == 'global':
                    applicable_routes.append(route)
                elif route.get('scope') == 'proxy' and proxy in route.get('proxy_hostnames', []):
                    applicable_routes.append(route)
            data_sections['routes'] = applicable_routes
            report['report']['metadata']['data_sources_queried'].append('config:routes')
        except Exception as e:
            console.print(f"    [yellow]⚠ Failed to get routes: {e}[/yellow]")
            data_sections['routes'] = []
        
        # 6. Get error logs
        console.print("  [dim]• Collecting error logs...[/dim]")
        try:
            errors_response = client.get_sync('/logs/errors', params={'hours': hours, 'include_warnings': True, 'limit': 500})
            all_errors = errors_response.get('errors', []) if isinstance(errors_response, dict) else []
            # Filter for IP and proxy
            data_sections['errors'] = [
                error for error in all_errors 
                if error.get('client_ip') == ip and error.get('proxy_hostname') == proxy
            ]
            report['report']['metadata']['data_sources_queried'].append('logs:errors')
        except Exception as e:
            console.print(f"    [yellow]⚠ Failed to get error logs: {e}[/yellow]")
            data_sections['errors'] = []
        
        # 7. Extract slow requests from main logs
        console.print("  [dim]• Identifying slow requests...[/dim]")
        slow_requests = []
        threshold_ms = 1000
        for log in data_sections.get('requests', []):
            response_time = log.get('response_time_ms', 0)
            if response_time >= threshold_ms:
                slow_requests.append({
                    'timestamp': log.get('timestamp'),
                    'trace_id': log.get('trace_id'),
                    'path': log.get('path'),
                    'response_time_ms': response_time,
                    'timeout': response_time > 30000,
                    'status_code': log.get('status_code')
                })
        data_sections['slow_requests'] = slow_requests
        
        # 8. Get certificate information
        console.print("  [dim]• Getting certificate information...[/dim]")
        try:
            cert_name = data_sections['proxy_config'].get('certificate_name', proxy)
            cert_response = client.get_sync(f'/certificates/{cert_name}')
            data_sections['certificates'] = [{
                'name': cert_name,
                'domains': cert_response.get('domains', []),
                'issuer': cert_response.get('issuer', 'Unknown'),
                'valid_from': cert_response.get('valid_from'),
                'valid_until': cert_response.get('valid_until'),
                'fingerprint': cert_response.get('fingerprint'),
                'status': cert_response.get('status', 'unknown'),
                'auto_renew': cert_response.get('auto_renew', True),
            }]
            report['report']['metadata']['data_sources_queried'].append('config:certificates')
        except Exception as e:
            console.print(f"    [yellow]⚠ Failed to get certificate: {e}[/yellow]")
            data_sections['certificates'] = []
        
        # 9. Reconstruct OAuth flows from events
        console.print("  [dim]• Reconstructing OAuth flows...[/dim]")
        oauth_flows = {}
        for event in data_sections.get('oauth_events', []):
            # Extract flow identifier from event data
            flow_id = None
            event_data = event.get('data', {})
            
            # Try to find flow ID in various places
            if isinstance(event_data, dict):
                # Check for state (authorization flow)
                flow_id = event_data.get('state')
                # Check for JWT ID (token validation)
                if not flow_id and 'jwt_claims' in event_data:
                    flow_id = event_data['jwt_claims'].get('jti')
                # Check for session ID
                if not flow_id:
                    flow_id = event_data.get('session_id')
            
            # Fall back to top-level session_id or create synthetic ID
            if not flow_id:
                flow_id = event.get('session_id')
            
            if not flow_id:
                # Create synthetic flow ID from timestamp and user
                timestamp = event.get('timestamp', '')
                user_id = event.get('user_id', 'unknown')
                if timestamp:
                    try:
                        if isinstance(timestamp, (int, float)):
                            # Unix timestamp
                            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                        else:
                            # ISO string
                            dt = datetime.fromisoformat(str(timestamp).replace('Z', '+00:00'))
                        flow_id = f"flow_{user_id}_{dt.strftime('%Y%m%d%H')}_{int(dt.minute / 5)}"
                    except:
                        flow_id = f"flow_{user_id}_unknown"
                else:
                    flow_id = f"flow_{user_id}_unknown"
            
            if flow_id not in oauth_flows:
                oauth_flows[flow_id] = {
                    'flow_id': flow_id,
                    'user_id': event.get('user_id', 'unknown'),
                    'client_id': event.get('client_id', 'unknown'),
                    'proxy_hostname': event.get('proxy_hostname', proxy),
                    'success': True,
                    'steps': [],
                    'start_time': event.get('timestamp'),
                    'end_time': event.get('timestamp'),
                    'scopes_granted': [],
                    'resources': [],
                    'error_reasons': []
                }
            
            # Update flow metadata
            flow = oauth_flows[flow_id]
            if event.get('user_id') and event['user_id'] != 'unknown':
                flow['user_id'] = event['user_id']
            if event.get('client_id') and event['client_id'] != 'unknown':
                flow['client_id'] = event['client_id']
            
            # Track success/failure
            if not event.get('success', True):
                flow['success'] = False
                if event.get('error_reason'):
                    flow['error_reasons'].append(event['error_reason'])
            
            # Extract scopes and resources from event data
            if isinstance(event_data, dict):
                if 'scopes_granted' in event_data:
                    flow['scopes_granted'] = event_data['scopes_granted']
                elif 'scope' in event_data:
                    flow['scopes_granted'] = event_data['scope'].split() if isinstance(event_data['scope'], str) else event_data['scope']
                if 'resources' in event_data or 'resource' in event_data:
                    flow['resources'] = event_data.get('resources', event_data.get('resource', []))
            
            flow['steps'].append({
                'step': event.get('event_type', 'unknown'),
                'timestamp': event.get('timestamp'),
                'timestamp_iso': event.get('timestamp_iso'),
                'success': event.get('success', True),
                'error_reason': event.get('error_reason'),
                'duration_ms': event.get('duration_ms'),
                'data': event_data
            })
            
            # Update end time
            if event.get('timestamp'):
                flow['end_time'] = event.get('timestamp')
        
        data_sections['oauth_flows'] = list(oauth_flows.values())
        
        if oauth_flows:
            successful_flows = sum(1 for f in oauth_flows.values() if f['success'])
            failed_flows = len(oauth_flows) - successful_flows
            console.print(f"    [green]✓ Reconstructed {len(oauth_flows)} OAuth flows ({successful_flows} successful, {failed_flows} failed)[/green]")
        
        # Calculate generation duration
        end_time = datetime.now(timezone.utc)
        generation_duration = int((end_time - start_time).total_seconds() * 1000)
        report['report']['metadata']['generation_duration_ms'] = generation_duration
        
        # Add all collected data to report
        for key, value in data_sections.items():
            report['report'][key] = value
        
        # Apply security masking unless disabled
        if not no_mask:
            console.print("  [dim]• Applying security masking...[/dim]")
            report = SecretMasker.mask_dict(report)
        else:
            console.print("  [yellow]⚠ Security masking disabled - report contains sensitive data![/yellow]")
            report['report']['metadata']['security_notice'] = 'WARNING: Security masking disabled - contains sensitive data'
        
        # Clean empty values from report
        console.print("  [dim]• Cleaning empty values...[/dim]")
        report = clean_empty_values(report)
        
        # Format output
        if output_format == 'json':
            output_content = json.dumps(report, indent=2, default=str)
        else:  # yaml
            output_content = yaml.dump(report, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        # Output report
        if output:
            with open(output, 'w') as f:
                f.write(output_content)
            console.print(f"\n[green]✓ Report written to {output}[/green]")
            console.print(f"  [dim]Size: {len(output_content):,} bytes[/dim]")
            console.print(f"  [dim]Requests analyzed: {len(data_sections.get('requests', []))}[/dim]")
            console.print(f"  [dim]OAuth events: {len(data_sections.get('oauth_events', []))}[/dim]")
            console.print(f"  [dim]Errors found: {len(data_sections.get('errors', []))}[/dim]")
        else:
            # Output to console with syntax highlighting
            if output_format == 'json':
                syntax = Syntax(output_content, "json", theme="monokai", line_numbers=False)
            else:
                syntax = Syntax(output_content, "yaml", theme="monokai", line_numbers=False)
            console.print(syntax)
            
    except Exception as e:
        ctx.handle_error(e)


@report_group.command('summary')
@click.argument('ip')
@click.argument('proxy')
@click.option('--hours', type=int, default=24, help='Hours of data to include')
@click.pass_obj
def generate_summary_report(ctx, ip, proxy, hours):
    """Generate a quick summary report for IP to proxy connections.
    
    This provides a condensed view of the connection statistics without
    the full data export.
    """
    try:
        client = ctx.ensure_client()
        
        console.print(f"[cyan]Generating summary for {ip} → {proxy} (last {hours} hours)...[/cyan]")
        
        # Get request logs
        ip_logs_response = client.get_sync(f'/logs/ip/{ip}', params={'hours': hours, 'limit': 1000})
        all_logs = ip_logs_response.get('logs', []) if isinstance(ip_logs_response, dict) else []
        proxy_logs = [log for log in all_logs if log.get('proxy_hostname') == proxy]
        
        # Calculate statistics
        total_requests = len(proxy_logs)
        
        # Status code distribution
        status_codes = {}
        response_times = []
        paths = {}
        methods = {}
        
        for log in proxy_logs:
            # Status codes
            status = log.get('status_code', 0)
            status_group = f"{status // 100}xx"
            status_codes[status_group] = status_codes.get(status_group, 0) + 1
            
            # Response times
            if 'response_time_ms' in log:
                response_times.append(log['response_time_ms'])
            
            # Paths
            path = log.get('path', 'unknown')
            paths[path] = paths.get(path, 0) + 1
            
            # Methods
            method = log.get('method', 'unknown')
            methods[method] = methods.get(method, 0) + 1
        
        # Calculate response time percentiles
        if response_times:
            response_times.sort()
            p50 = response_times[len(response_times) // 2]
            p95 = response_times[int(len(response_times) * 0.95)]
            p99 = response_times[int(len(response_times) * 0.99)]
            avg_response_time = sum(response_times) / len(response_times)
        else:
            p50 = p95 = p99 = avg_response_time = 0
        
        # Top paths
        top_paths = sorted(paths.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Display summary
        from rich.table import Table
        
        # Overview table
        overview = Table(title=f"Connection Summary: {ip} → {proxy}")
        overview.add_column("Metric", style="cyan")
        overview.add_column("Value", style="yellow")
        
        overview.add_row("Time Range", f"Last {hours} hours")
        overview.add_row("Total Requests", str(total_requests))
        overview.add_row("Avg Response Time", f"{avg_response_time:.2f}ms")
        overview.add_row("P50 Response Time", f"{p50:.2f}ms")
        overview.add_row("P95 Response Time", f"{p95:.2f}ms")
        overview.add_row("P99 Response Time", f"{p99:.2f}ms")
        
        console.print(overview)
        
        # Status code distribution
        if status_codes:
            status_table = Table(title="Status Code Distribution")
            status_table.add_column("Status", style="cyan")
            status_table.add_column("Count", style="yellow")
            status_table.add_column("Percentage", style="green")
            
            for status, count in sorted(status_codes.items()):
                percentage = (count / total_requests) * 100
                status_table.add_row(status, str(count), f"{percentage:.1f}%")
            
            console.print(status_table)
        
        # Top paths
        if top_paths:
            paths_table = Table(title="Top 5 Paths")
            paths_table.add_column("Path", style="cyan")
            paths_table.add_column("Requests", style="yellow")
            
            for path, count in top_paths:
                paths_table.add_row(path, str(count))
            
            console.print(paths_table)
        
        # HTTP methods
        if methods:
            methods_table = Table(title="HTTP Methods")
            methods_table.add_column("Method", style="cyan")
            methods_table.add_column("Count", style="yellow")
            
            for method, count in sorted(methods.items()):
                methods_table.add_row(method, str(count))
            
            console.print(methods_table)
            
    except Exception as e:
        ctx.handle_error(e)