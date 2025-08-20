"""OAuth administration commands."""

import click
from rich.console import Console
from rich.prompt import Confirm

console = Console()


@click.group('oauth')
def oauth_group():
    """OAuth administration and management."""
    pass


# Client management
@oauth_group.group('client')
def oauth_client():
    """Manage OAuth clients."""
    pass


@oauth_client.command('list')
@click.option('--active-only', is_flag=True, help='Show only active clients')
@click.option('--page', type=int, default=1, help='Page number (default: 1)')
@click.option('--per-page', type=int, default=50, help='Items per page (default: 50, max: 100)')
@click.pass_obj
def list_clients(ctx, active_only, page, per_page):
    """List OAuth clients."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'page': page,
            'per_page': min(per_page, 100)  # Enforce API limit
        }
        if active_only:
            params['active_only'] = 'true'
        
        response = client.get_sync('/oauth/clients', params)
        
        # Extract clients array from response
        clients = response.get('clients', []) if isinstance(response, dict) else response
        
        # Add summary info if available
        if isinstance(response, dict) and 'summary' in response:
            summary = response['summary']
            title = f"OAuth Clients (Total: {summary.get('total_clients', 0)}, Active: {summary.get('active_clients', 0)})"
        else:
            title = "OAuth Clients"
        
        ctx.output(clients, title=title, data_type='oauth_clients')
    except Exception as e:
        ctx.handle_error(e)


@oauth_client.command('show')
@click.argument('client-id')
@click.pass_obj
def show_client(ctx, client_id):
    """Show OAuth client details."""
    try:
        client = ctx.ensure_client()
        oauth_client = client.get_sync(f'/oauth/clients/{client_id}')
        ctx.output(oauth_client, title=f"OAuth Client: {client_id}")
    except Exception as e:
        ctx.handle_error(e)


# Session management
@oauth_group.group('session')
def oauth_session():
    """Manage OAuth sessions."""
    pass


@oauth_session.command('list')
@click.pass_obj
def list_sessions(ctx):
    """List active OAuth sessions."""
    try:
        client = ctx.ensure_client()
        sessions = client.get_sync('/oauth/sessions')
        ctx.output(sessions, title="Active OAuth Sessions", data_type='oauth_sessions')
    except Exception as e:
        ctx.handle_error(e)


@oauth_session.command('revoke')
@click.argument('session-id')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
@click.pass_obj
def revoke_session(ctx, session_id, force):
    """Revoke an OAuth session."""
    try:
        if not force:
            if not Confirm.ask(f"Revoke session '{session_id}'?", default=False):
                return
        
        client = ctx.ensure_client()
        client.delete_sync(f'/oauth/sessions/{session_id}')
        
        console.print(f"[green]Session '{session_id}' revoked successfully![/green]")
    except Exception as e:
        ctx.handle_error(e)


# Metrics and health
@oauth_group.command('metrics')
@click.pass_obj
def oauth_metrics(ctx):
    """Show OAuth system metrics."""
    try:
        client = ctx.ensure_client()
        metrics = client.get_sync('/oauth/metrics')
        ctx.output(metrics, title="OAuth Metrics")
    except Exception as e:
        ctx.handle_error(e)


@oauth_group.command('health')
@click.pass_obj
def oauth_health(ctx):
    """Check OAuth integration health."""
    try:
        client = ctx.ensure_client()
        health = client.get_sync('/oauth/health')
        
        if ctx.output_format == 'json':
            ctx.output(health)
        else:
            # Format health status nicely
            status = health.get('status', 'unknown')
            if status == 'healthy':
                console.print("[green]✓ OAuth system is healthy[/green]")
            else:
                console.print(f"[red]✗ OAuth system status: {status}[/red]")
            
            if health.get('github_connected'):
                console.print("[green]✓ GitHub OAuth connected[/green]")
            else:
                console.print("[yellow]⚠ GitHub OAuth not configured[/yellow]")
            
            if health.get('jwks_available'):
                console.print("[green]✓ JWKS endpoint available[/green]")
            else:
                console.print("[red]✗ JWKS endpoint not available[/red]")
    except Exception as e:
        ctx.handle_error(e)


# Token operations
@oauth_group.command('register')
@click.argument('name')
@click.option('--redirect-uri', default='urn:ietf:wg:oauth:2.0:oob', help='OAuth redirect URI')
@click.option('--scope', default='mcp:read mcp:write', help='OAuth scopes')
@click.pass_obj
def register_client(ctx, name, redirect_uri, scope):
    """Register a new OAuth client."""
    try:
        client = ctx.ensure_client()
        
        data = {
            'software_id': f'oauth-proxy-client-{name}',
            'software_version': '1.0.0',
            'client_name': name,
            'redirect_uris': [redirect_uri],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'scope': scope,
        }
        
        result = client.post_sync('/register', data)
        
        console.print(f"[green]OAuth client registered successfully![/green]")
        console.print(f"Client ID: [bold yellow]{result['client_id']}[/bold yellow]")
        console.print(f"Client Secret: [bold yellow]{result['client_secret']}[/bold yellow]")
        console.print("[dim]Save these credentials - they cannot be retrieved again![/dim]")
        
        if 'registration_access_token' in result:
            console.print(f"Registration Token: {result['registration_access_token']}")
        if 'registration_client_uri' in result:
            console.print(f"Management URI: {result['registration_client_uri']}")
    except Exception as e:
        ctx.handle_error(e)


# Additional OAuth commands for missing endpoints

# Admin subgroup
@oauth_group.group('admin')
def oauth_admin():
    """OAuth administration tasks."""
    pass


@oauth_admin.command('setup-status')
@click.pass_obj
def admin_setup_status(ctx):
    """Check OAuth setup status."""
    try:
        client = ctx.ensure_client()
        status = client.get_sync('/oauth/admin/setup-status')
        
        if ctx.output_format == 'json':
            ctx.output(status)
        else:
            if status.get('configured'):
                console.print("[green]✓ OAuth is fully configured[/green]")
            else:
                console.print("[yellow]⚠ OAuth setup incomplete[/yellow]")
            
            if status.get('routes_configured'):
                console.print("[green]✓ Routes configured[/green]")
            else:
                console.print("[red]✗ Routes not configured[/red]")
            
            if status.get('keys_configured'):
                console.print("[green]✓ JWT keys configured[/green]")
            else:
                console.print("[red]✗ JWT keys not configured[/red]")
            
            if status.get('github_configured'):
                console.print("[green]✓ GitHub OAuth configured[/green]")
            else:
                console.print("[red]✗ GitHub OAuth not configured[/red]")
    except Exception as e:
        ctx.handle_error(e)


@oauth_admin.command('setup-routes')
@click.argument('domain')
@click.pass_obj
def admin_setup_routes(ctx, domain):
    """Setup OAuth routes for a domain."""
    try:
        client = ctx.ensure_client()
        data = {'domain': domain}
        result = client.post_sync('/oauth/admin/setup-routes', data)
        
        console.print(f"[green]OAuth routes configured for domain: {domain}![/green]")
        ctx.output(result)
    except Exception as e:
        ctx.handle_error(e)


# Proxy management
@oauth_group.group('proxy')
def oauth_proxy():
    """OAuth proxy management."""
    pass


@oauth_proxy.command('list')
@click.pass_obj
def list_oauth_proxies(ctx):
    """List OAuth-enabled proxies."""
    try:
        client = ctx.ensure_client()
        proxies = client.get_sync('/oauth/proxies')
        ctx.output(proxies, title="OAuth-Enabled Proxies")
    except Exception as e:
        ctx.handle_error(e)


@oauth_proxy.command('sessions')
@click.argument('hostname')
@click.pass_obj
def proxy_sessions(ctx, hostname):
    """Get sessions for a specific proxy."""
    try:
        client = ctx.ensure_client()
        sessions = client.get_sync(f'/oauth/proxies/{hostname}/sessions')
        ctx.output(sessions, title=f"Sessions for proxy: {hostname}")
    except Exception as e:
        ctx.handle_error(e)


# Token management
@oauth_group.group('token')
def oauth_token():
    """OAuth token management."""
    pass


@oauth_token.command('list')
@click.option('--token-type', help='Filter by token type (access/refresh)')
@click.option('--client-id', help='Filter by client ID')
@click.option('--username', help='Filter by username')
@click.option('--include-expired', is_flag=True, help='Include expired tokens')
@click.option('--page', type=int, default=1, help='Page number (default: 1)')
@click.option('--per-page', type=int, default=50, help='Items per page (default: 50, max: 100)')
@click.pass_obj
def list_oauth_tokens(ctx, token_type, client_id, username, include_expired, page, per_page):
    """List all OAuth access and refresh tokens."""
    try:
        client = ctx.ensure_client()
        
        params = {
            'page': page,
            'per_page': min(per_page, 100)  # Enforce API limit
        }
        if token_type:
            params['token_type'] = token_type
        if client_id:
            params['client_id'] = client_id
        if username:
            params['username'] = username
        if include_expired:
            params['include_expired'] = 'true'
        
        response = client.get_sync('/oauth/tokens', params)
        
        # Extract tokens array from response
        tokens = response.get('tokens', []) if isinstance(response, dict) else response
        
        # Add summary info if available
        if isinstance(response, dict) and 'summary' in response:
            summary = response['summary']
            title = f"OAuth Tokens (Total: {summary.get('total_tokens', 0)}, Active: {summary.get('active_tokens', 0)})"
        else:
            title = "OAuth Tokens"
        
        ctx.output(tokens, title=title, data_type='oauth_tokens')
    except Exception as e:
        ctx.handle_error(e)


@oauth_token.command('show')
@click.argument('jti')
@click.pass_obj
def show_oauth_token(ctx, jti):
    """Show OAuth token details."""
    try:
        client = ctx.ensure_client()
        token = client.get_sync(f'/oauth/tokens/{jti}')
        ctx.output(token, title=f"OAuth Token: {jti}")
    except Exception as e:
        ctx.handle_error(e)


# Client tokens
@oauth_client.command('tokens')
@click.argument('client-id')
@click.pass_obj
def list_client_tokens(ctx, client_id):
    """List tokens for a specific OAuth client."""
    try:
        client = ctx.ensure_client()
        tokens = client.get_sync(f'/oauth/clients/{client_id}/tokens')
        ctx.output(tokens, title=f"Tokens for client: {client_id}", data_type='oauth_tokens')
    except Exception as e:
        ctx.handle_error(e)


# Session details
@oauth_session.command('show')
@click.argument('session-id')
@click.pass_obj
def show_session(ctx, session_id):
    """Show OAuth session details."""
    try:
        client = ctx.ensure_client()
        session = client.get_sync(f'/oauth/sessions/{session_id}')
        ctx.output(session, title=f"OAuth Session: {session_id}")
    except Exception as e:
        ctx.handle_error(e)