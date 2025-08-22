"""Log query and analysis commands."""

import click
import asyncio
import time
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.prompt import Confirm

console = Console()


@click.group('log')
def log_group():
    """Query and analyze logs."""
    pass


@log_group.command('search')
@click.option('--query', '-q', help='Search query')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--hostname', help='Filter by hostname')
@click.option('--status', type=int, help='Filter by HTTP status code')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def search_logs(ctx, query, hours, hostname, status, limit):
    """Search logs with filters."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        if query:
            params['q'] = query
        if hostname:
            params['hostname'] = hostname
        if status:
            params['status'] = status
        
        logs = client.get_sync('/logs/search', params)
        ctx.output(logs, title="Log Search Results", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('ip')
@click.argument('client_ip')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def logs_by_ip(ctx, client_ip, hours, limit):
    """Query logs by client IP address."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        logs = client.get_sync(f'/logs/ip/{client_ip}', params)
        ctx.output(logs, title=f"Logs from IP: {client_ip}", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('oauth-client')
@click.argument('client-id')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def logs_oauth_client(ctx, client_id, hours, limit):
    """Query logs by OAuth client ID."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        logs = client.get_sync(f'/logs/client/{client_id}', params)
        ctx.output(logs, title=f"Logs from Client: {client_id}", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('errors')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--include-warnings', is_flag=True, help='Include 4xx errors')
@click.option('--limit', type=int, default=50, help='Maximum results')
@click.pass_obj
def show_errors(ctx, hours, include_warnings, limit):
    """Show recent errors."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'include_warnings': include_warnings,
            'limit': limit,
        }
        
        errors = client.get_sync('/logs/errors', params)
        ctx.output(errors, title="Recent Errors", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('stats')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.pass_obj
def event_stats(ctx, hours):
    """Show event statistics."""
    try:
        client = ctx.ensure_client()
        
        params = {'hours': hours}
        stats = client.get_sync('/logs/events', params)
        ctx.output(stats, title="Event Statistics")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('follow')
@click.option('--interval', type=int, default=2, help='Update interval in seconds')
@click.option('--hostname', help='Filter by hostname')
@click.option('--status', type=int, help='Filter by status code')
@click.pass_obj
def follow_logs(ctx, interval, hostname, status):
    """Follow logs in real-time."""
    try:
        client = ctx.ensure_client()
        
        console.print(f"[yellow]Following logs (Ctrl+C to stop)...[/yellow]")
        console.print(f"Update interval: {interval} seconds")
        
        if hostname:
            console.print(f"Filtering by hostname: {hostname}")
        if status:
            console.print(f"Filtering by status: {status}")
        
        last_timestamp = None
        
        try:
            while True:
                params = {
                    'hours': 1,  # Last 1 hour
                    'limit': 20,
                }
                
                if hostname:
                    params['hostname'] = hostname
                if status:
                    params['status'] = status
                
                response = client.get_sync('/logs/search', params)
                
                # Extract logs from response
                if isinstance(response, dict):
                    logs = response.get('logs', [])
                else:
                    logs = response if isinstance(response, list) else []
                
                # Filter to only new logs
                if last_timestamp and logs:
                    new_logs = [l for l in logs if l.get('timestamp', '') > last_timestamp]
                else:
                    new_logs = logs
                
                # Filter out the follow command's own requests to /logs/search
                # to avoid noise in the output
                new_logs = [
                    log for log in new_logs 
                    if not (
                        log.get('path') == '/logs/search' and 
                        log.get('method') == 'GET' and
                        'oauth-https-proxy-client' in log.get('user_agent', '')
                    )
                ]
                
                # Display new logs using multi-line format
                if new_logs:
                    # Use the enhanced table formatter's multi-line format
                    from ..formatters.enhanced_table import EnhancedTableFormatter
                    formatter = EnhancedTableFormatter()
                    
                    # Format and display each log entry without summary
                    for log in new_logs:
                        # Format single log with multi-line format, no summary for follow mode
                        formatted = formatter._format_logs_multiline([log], show_summary=False)
                        console.print(formatted)
                
                # Update last timestamp
                if logs:
                    last_timestamp = logs[0].get('timestamp')
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopped following logs.[/yellow]")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('hostname')
@click.argument('hostname')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def logs_by_hostname(ctx, hostname, hours, limit):
    """Query logs by client hostname (reverse DNS of client IP)."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        logs = client.get_sync(f'/logs/host/{hostname}', params)
        ctx.output(logs, title=f"Logs from client FQDN: {hostname}", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('proxy')
@click.argument('hostname')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def logs_by_proxy(ctx, hostname, hours, limit):
    """Query logs by proxy hostname."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        # Note: This uses search endpoint with hostname filter
        # since there's no dedicated proxy hostname endpoint
        params['hostname'] = hostname
        logs = client.get_sync('/logs/search', params)
        ctx.output(logs, title=f"Logs for proxy hostname: {hostname}", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('stats')
@click.option('--hours', type=int, default=24, help='Hours to look back')
@click.pass_obj
def log_stats(ctx, hours):
    """Show comprehensive log statistics."""
    try:
        client = ctx.ensure_client()
        
        params = {'hours': hours}
        stats = client.get_sync('/logs/stats', params)
        
        # Display statistics in a formatted way
        if ctx.output_format == 'table' or ctx.output_format == 'auto':
            # Create overview table
            overview = Table(title=f"Log Statistics (Last {hours} hours)")
            overview.add_column("Metric", style="cyan")
            overview.add_column("Value", style="yellow")
            
            if 'total_requests' in stats:
                overview.add_row("Total Requests", str(stats['total_requests']))
            if 'unique_ips' in stats:
                overview.add_row("Unique IPs", str(stats['unique_ips']))
            if 'error_rate' in stats:
                overview.add_row("Error Rate", f"{stats['error_rate']:.2%}")
            if 'avg_response_time' in stats:
                overview.add_row("Avg Response Time", f"{stats['avg_response_time']:.2f}ms")
            
            console.print(overview)
            
            # Show top paths if available
            if 'top_paths' in stats and stats['top_paths']:
                paths_table = Table(title="Top Paths")
                paths_table.add_column("Path", style="cyan")
                paths_table.add_column("Count", style="yellow")
                
                for path, count in stats['top_paths'][:10]:
                    paths_table.add_row(path, str(count))
                
                console.print(paths_table)
            
            # Show status code distribution
            if 'status_codes' in stats and stats['status_codes']:
                status_table = Table(title="Status Code Distribution")
                status_table.add_column("Status", style="cyan")
                status_table.add_column("Count", style="yellow")
                
                for status, count in sorted(stats['status_codes'].items()):
                    status_table.add_row(str(status), str(count))
                
                console.print(status_table)
        else:
            ctx.output(stats, title="Log Statistics")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('oauth')
@click.argument('client_ip')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def oauth_activity(ctx, client_ip, hours, limit):
    """Show OAuth activity summary for a client IP."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        activity = client.get_sync(f'/logs/oauth/{client_ip}', params)
        
        # Display OAuth activity summary
        if ctx.output_format == 'table' or ctx.output_format == 'auto':
            console.print(f"\n[bold]OAuth Activity for IP: {client_ip}[/bold]")
            
            if 'summary' in activity:
                summary = activity['summary']
                console.print(f"  Authorization Attempts: {summary.get('auth_attempts', 0)}")
                console.print(f"  Successful Logins: {summary.get('successful_logins', 0)}")
                console.print(f"  Failed Logins: {summary.get('failed_logins', 0)}")
                console.print(f"  Token Requests: {summary.get('token_requests', 0)}")
                console.print(f"  Active Sessions: {summary.get('active_sessions', 0)}")
            
            if 'recent_activity' in activity and activity['recent_activity']:
                table = Table(title="Recent OAuth Events")
                table.add_column("Time", style="dim")
                table.add_column("Event", style="cyan")
                table.add_column("Status", style="yellow")
                table.add_column("Details")
                
                for event in activity['recent_activity'][:20]:
                    table.add_row(
                        event.get('timestamp', 'N/A'),
                        event.get('event_type', 'N/A'),
                        event.get('status', 'N/A'),
                        event.get('details', '')
                    )
                
                console.print(table)
        else:
            ctx.output(activity, title=f"OAuth Activity: {client_ip}")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('oauth-debug')
@click.argument('client_ip')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def oauth_debug(ctx, client_ip, hours, limit):
    """Full OAuth flow debugging for a client IP."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        debug_info = client.get_sync(f'/logs/oauth-debug/{client_ip}', params)
        
        # Display detailed OAuth debugging information
        if ctx.output_format == 'table' or ctx.output_format == 'auto':
            console.print(f"\n[bold]OAuth Debug Information for IP: {client_ip}[/bold]\n")
            
            # Show OAuth flows
            if 'flows' in debug_info and debug_info['flows']:
                for i, flow in enumerate(debug_info['flows'], 1):
                    console.print(f"[bold cyan]Flow {i}:[/bold cyan]")
                    console.print(f"  Session ID: {flow.get('session_id', 'N/A')}")
                    console.print(f"  Client ID: {flow.get('client_id', 'N/A')}")
                    console.print(f"  Start Time: {flow.get('start_time', 'N/A')}")
                    console.print(f"  End Time: {flow.get('end_time', 'N/A')}")
                    console.print(f"  Status: {flow.get('status', 'N/A')}")
                    
                    if 'steps' in flow:
                        console.print("  Steps:")
                        for step in flow['steps']:
                            status_icon = "✓" if step.get('success') else "✗"
                            console.print(f"    {status_icon} {step.get('name', 'N/A')}: {step.get('message', '')}")
                    
                    if 'errors' in flow and flow['errors']:
                        console.print("  [red]Errors:[/red]")
                        for error in flow['errors']:
                            console.print(f"    - {error}")
                    
                    console.print()
            
            # Show detailed request/response logs
            if 'detailed_logs' in debug_info and debug_info['detailed_logs']:
                table = Table(title="Detailed OAuth Requests")
                table.add_column("Time", style="dim")
                table.add_column("Method", style="cyan")
                table.add_column("Path")
                table.add_column("Status")
                table.add_column("Headers/Body", max_width=50)
                
                for log in debug_info['detailed_logs'][:30]:
                    status = str(log.get('status', 'N/A'))
                    if status.startswith('2'):
                        status_style = "[green]" + status + "[/green]"
                    elif status.startswith('4'):
                        status_style = "[yellow]" + status + "[/yellow]"
                    elif status.startswith('5'):
                        status_style = "[red]" + status + "[/red]"
                    else:
                        status_style = status
                    
                    details = []
                    if log.get('request_headers'):
                        details.append("Headers: " + str(log['request_headers'])[:50])
                    if log.get('request_body'):
                        details.append("Body: " + str(log['request_body'])[:50])
                    
                    table.add_row(
                        log.get('timestamp', 'N/A'),
                        log.get('method', 'N/A'),
                        log.get('path', 'N/A'),
                        status_style,
                        "\n".join(details)
                    )
                
                console.print(table)
        else:
            ctx.output(debug_info, title=f"OAuth Debug: {client_ip}")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('oauth-flow')
@click.option('--client-id', help='Filter by OAuth client ID')
@click.option('--username', help='Filter by username')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.pass_obj
def oauth_flow(ctx, client_id, username, hours):
    """Track OAuth authorization flows."""
    try:
        client = ctx.ensure_client()
        
        params = {'hours': hours}
        
        if client_id:
            params['client_id'] = client_id
        if username:
            params['username'] = username
        
        flows = client.get_sync('/logs/oauth-flow', params)
        ctx.output(flows, title="OAuth Flows")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('clear')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def clear_logs(ctx, force):
    """Clear all log entries from Redis."""
    try:
        if not force:
            console.print("[yellow]WARNING: This will delete all log entries from Redis![/yellow]")
            if not Confirm.ask("Are you sure you want to clear all logs?", default=False):
                return
        
        client = ctx.ensure_client()
        # delete_sync returns boolean, but we want the response data
        # So we'll make a direct request to get the response
        try:
            response = client.request_sync('DELETE', '/logs')
            if response.status_code == 200:
                console.print("[green]✓ All logs cleared successfully![/green]")
                result = response.json()
                if isinstance(result, dict) and 'cleared_count' in result:
                    console.print(f"  Deleted {result['cleared_count']} log entries")
            else:
                raise Exception(f"Failed to clear logs: {response.status_code}")
        except Exception as delete_error:
            # Fallback to simple delete_sync
            success = client.delete_sync('/logs')
            if success:
                console.print("[green]✓ All logs cleared successfully![/green]")
            else:
                raise Exception("Failed to clear logs")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('test')
@click.pass_obj
def test_logging(ctx):
    """Test the logging system."""
    try:
        client = ctx.ensure_client()
        
        console.print("[yellow]Testing logging system...[/yellow]")
        
        # Generate test log entries
        result = client.post_sync('/logs/test')
        
        if result.get('success'):
            console.print("[green]✓ Logging system test successful![/green]")
            console.print(f"  Generated {result.get('entries_created', 0)} test entries")
            
            # Try to retrieve the test entries
            params = {'hours': 1, 'limit': 5}
            recent_logs = client.get_sync('/logs/search', params)
            
            if recent_logs:
                console.print(f"  Retrieved {len(recent_logs)} recent log entries")
                console.print("[green]✓ Log retrieval working correctly![/green]")
            else:
                console.print("[yellow]⚠ No recent logs found[/yellow]")
        else:
            console.print("[red]✗ Logging system test failed[/red]")
            if result.get('error'):
                console.print(f"  Error: {result['error']}")
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('user')
@click.argument('user-id')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def logs_by_user(ctx, user_id, hours, limit):
    """Query logs by authenticated user ID."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        logs = client.get_sync(f'/logs/user/{user_id}', params)
        ctx.output(logs, title=f"Logs from User: {user_id}", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('session')
@click.argument('session-id')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def logs_by_session(ctx, session_id, hours, limit):
    """Query logs by session ID."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        logs = client.get_sync(f'/logs/session/{session_id}', params)
        ctx.output(logs, title=f"Logs for Session: {session_id}", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('method')
@click.argument('method')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def logs_by_method(ctx, method, hours, limit):
    """Query logs by HTTP method."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        logs = client.get_sync(f'/logs/method/{method}', params)
        ctx.output(logs, title=f"Logs for Method: {method}", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('status')
@click.argument('code')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def logs_by_status(ctx, code, hours, limit):
    """Query logs by status code."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        logs = client.get_sync(f'/logs/status/{code}', params)
        ctx.output(logs, title=f"Logs with Status: {code}", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('slow')
@click.option('--threshold', type=int, default=1000, help='Response time threshold in milliseconds')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=50, help='Maximum results')
@click.pass_obj
def logs_slow_requests(ctx, threshold, hours, limit):
    """Query slow requests above threshold."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'threshold_ms': threshold,
            'hours': hours,
            'limit': limit,
        }
        
        logs = client.get_sync('/logs/slow', params)
        ctx.output(logs, title=f"Slow Requests (>{threshold}ms)", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('path')
@click.argument('pattern')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def logs_by_path(ctx, pattern, hours, limit):
    """Query logs by path pattern."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'pattern': pattern,
            'hours': hours,
            'limit': limit,
        }
        
        logs = client.get_sync('/logs/path', params)
        ctx.output(logs, title=f"Logs matching path: {pattern}", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)


@log_group.command('oauth-user')
@click.argument('username')
@click.option('--hours', type=int, default=1, help='Hours to look back')
@click.option('--limit', type=int, default=100, help='Maximum results')
@click.pass_obj
def logs_by_oauth_user(ctx, username, hours, limit):
    """Query logs by OAuth username."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'hours': hours,
            'limit': limit,
        }
        
        logs = client.get_sync(f'/logs/oauth/user/{username}', params)
        ctx.output(logs, title=f"Logs for OAuth User: {username}", data_type='logs')
    except Exception as e:
        ctx.handle_error(e)