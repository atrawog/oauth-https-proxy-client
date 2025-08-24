"""OAuth administration commands."""

import sys
import time
import asyncio
import jwt
from datetime import datetime
import click
from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

console = Console()


@click.group('oauth')
def oauth_group():
    """OAuth administration and management."""
    pass


# Helper function to display token information
def display_token_info(access_token, refresh_token=None, scope=None, title="OAuth Token Information"):
    """Display detailed token information in a table."""
    try:
        # Decode JWT token to show full information
        claims = jwt.decode(access_token, options={"verify_signature": False})
        
        # Create a table for token information
        table = Table(title=title, show_header=True, header_style="bold cyan")
        table.add_column("Field", style="bright_blue", width=20)
        table.add_column("Value", style="white")
        
        # Add user information
        if 'username' in claims:
            table.add_row("Username", claims['username'])
        if 'sub' in claims:
            table.add_row("User ID", str(claims['sub']))
        if 'email' in claims:
            table.add_row("Email", claims['email'])
        if 'name' in claims:
            table.add_row("Name", claims['name'])
        
        # Add scope
        table.add_row("Scope", scope or claims.get('scope', 'N/A'))
        
        # Add audience
        if 'aud' in claims:
            aud = claims['aud']
            if isinstance(aud, list):
                aud_str = ', '.join(aud)
            else:
                aud_str = str(aud)
            table.add_row("Audience (aud)", aud_str)
        
        # Add issuer
        if 'iss' in claims:
            table.add_row("Issuer", claims['iss'])
        
        # Add client ID
        if 'azp' in claims:
            table.add_row("Client ID", claims['azp'])
        
        # Add timestamps in ISO format
        if 'iat' in claims:
            iat_time = datetime.fromtimestamp(claims['iat'])
            table.add_row("Issued At", iat_time.isoformat())
        
        if 'exp' in claims:
            exp_time = datetime.fromtimestamp(claims['exp'])
            table.add_row("Expires At", exp_time.isoformat())
            
            # Calculate time remaining
            remaining = int((claims['exp'] - time.time()) / 60)
            if remaining > 0:
                table.add_row("Time Remaining", f"{remaining} minutes")
            else:
                table.add_row("Time Remaining", "[red]Expired[/red]")
        
        # Add refresh token status
        if refresh_token:
            table.add_row("Refresh Token", "[green]✓ Available[/green]")
        else:
            table.add_row("Refresh Token", "[yellow]✗ Not available[/yellow]")
        
        # Add token ID if present
        if 'jti' in claims:
            table.add_row("Token ID (jti)", claims['jti'])
        
        console.print(table)
        return True
    except Exception as e:
        console.print(f"[yellow]Could not decode token details: {e}[/yellow]")
        return False


# Authentication commands
@oauth_group.command('login')
@click.option('--domain', default='localhost', help='OAuth server domain')
@click.option('--no-browser', is_flag=True, help='Do not open browser automatically')
@click.option('--force', is_flag=True, help='Force new login even if valid token exists')
@click.pass_obj
def oauth_login(ctx, domain, no_browser, force):
    """Authenticate via GitHub Device Flow and save tokens to .env."""
    try:
        from ..core.auth import TokenManager, DeviceFlowAuth
        
        # First check if we already have a valid token (unless --force is used)
        if not force:
            manager = TokenManager(ctx.config)
            
            # If we have a valid token, just show it and exit
            if manager.access_token and manager.is_valid():
                console.print("\n[green]✓ Token is already valid![/green]\n")
                display_token_info(
                    manager.access_token, 
                    manager.refresh_token, 
                    manager.scope,
                    title="Current OAuth Token (Already Valid)"
                )
                console.print("\n[dim]Use --force flag to get a new token anyway[/dim]")
                return
            
            # If we have an expired token with refresh token, try to refresh
            if manager.access_token and manager.refresh_token and not manager.is_valid():
                console.print("[yellow]Token expired, attempting to refresh...[/yellow]")
                
                # Try to refresh the token
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    success = loop.run_until_complete(manager.refresh())
                finally:
                    loop.close()
                
                if success:
                    console.print("\n[green]✓ Token refreshed successfully![/green]\n")
                    display_token_info(
                        manager.access_token,
                        manager.refresh_token,
                        manager.scope,
                        title="Refreshed OAuth Token"
                    )
                    console.print("\n[green]Token automatically saved to .env[/green]")
                    return
                else:
                    console.print("[yellow]Refresh failed, requesting new token...[/yellow]\n")
        
        # If we get here, we need to do a full device flow login
        auth = DeviceFlowAuth(domain)
        
        # Start device flow
        tokens = auth.authenticate(open_browser=not no_browser)
        
        if tokens:
            # Save ALL tokens to .env
            auth.save_tokens_to_env(
                access_token=tokens['access_token'],
                refresh_token=tokens['refresh_token'],
                expires_at=tokens['expires_at'],
                scope=tokens['scope']
            )
            
            console.print("\n[green]✓ Authentication successful![/green]\n")
            
            # Display token information using helper function
            display_token_info(
                tokens['access_token'],
                tokens.get('refresh_token'),
                tokens.get('scope'),
                title="New OAuth Token"
            )
            
            console.print("\n[green]Tokens saved to .env[/green]")
            console.print("[dim]To reload environment: source .env[/dim]")
        else:
            console.print("[red]✗ Authentication failed[/red]")
            sys.exit(1)
    except Exception as e:
        ctx.handle_error(e)


@oauth_group.command('status')
@click.option('--quiet', is_flag=True, help='Quiet mode for scripting')
@click.option('--detailed', '-d', is_flag=True, help='Show detailed token information')
@click.pass_obj
def oauth_status(ctx, quiet, detailed):
    """Show current OAuth token status."""
    try:
        from ..core.auth import TokenManager
        
        manager = TokenManager(ctx.config)
        
        if not manager.access_token:
            if not quiet:
                console.print("[yellow]No OAuth token configured[/yellow]")
                console.print("Run: proxy-client oauth login")
            sys.exit(1)
        
        if manager.is_valid():
            if not quiet:
                if detailed:
                    # Show detailed token information
                    try:
                        claims = jwt.decode(manager.access_token, options={"verify_signature": False})
                        
                        table = Table(title="Current OAuth Token", show_header=True, header_style="bold cyan")
                        table.add_column("Field", style="bright_blue", width=20)
                        table.add_column("Value", style="white")
                        
                        # Add status
                        remaining = int((manager.expires_at - time.time()) / 60) if manager.expires_at else 0
                        table.add_row("Status", f"[green]✓ Valid ({remaining} min remaining)[/green]")
                        
                        # Add user information
                        if 'username' in claims:
                            table.add_row("Username", claims['username'])
                        if 'sub' in claims:
                            table.add_row("User ID", str(claims['sub']))
                        if 'email' in claims:
                            table.add_row("Email", claims['email'])
                        if 'name' in claims:
                            table.add_row("Name", claims['name'])
                        
                        # Add scope
                        table.add_row("Scope", manager.scope or claims.get('scope', 'N/A'))
                        
                        # Add audience
                        if 'aud' in claims:
                            aud = claims['aud']
                            if isinstance(aud, list):
                                aud_str = ', '.join(aud)
                            else:
                                aud_str = str(aud)
                            table.add_row("Audience (aud)", aud_str)
                        
                        # Add issuer
                        if 'iss' in claims:
                            table.add_row("Issuer", claims['iss'])
                        
                        # Add client ID
                        if 'azp' in claims:
                            table.add_row("Client ID", claims['azp'])
                        
                        # Add timestamps in ISO format
                        if 'iat' in claims:
                            iat_time = datetime.fromtimestamp(claims['iat'])
                            table.add_row("Issued At", iat_time.isoformat())
                        
                        if manager.expires_at:
                            exp_time = datetime.fromtimestamp(manager.expires_at)
                            table.add_row("Expires At", exp_time.isoformat())
                        
                        # Add refresh token status
                        if manager.refresh_token:
                            table.add_row("Refresh Token", "[green]✓ Available[/green]")
                        else:
                            table.add_row("Refresh Token", "[yellow]✗ Not available[/yellow]")
                        
                        # Add token ID if present
                        if 'jti' in claims:
                            table.add_row("Token ID (jti)", claims['jti'])
                        
                        console.print(table)
                    except Exception as e:
                        # Fallback to simple display
                        console.print(f"[yellow]Could not decode token details: {e}[/yellow]")
                        remaining = int((manager.expires_at - time.time()) / 60) if manager.expires_at else 0
                        console.print(f"[green]✓ Token valid for {remaining} minutes[/green]")
                        if manager.scope:
                            console.print(f"Scopes: {manager.scope}")
                else:
                    # Simple display (default)
                    remaining = int((manager.expires_at - time.time()) / 60) if manager.expires_at else 0
                    console.print(f"[green]✓ Token valid for {remaining} minutes[/green]")
                    
                    if manager.scope:
                        console.print(f"Scopes: {manager.scope}")
                    
                    if manager.refresh_token:
                        console.print("[green]✓ Refresh token available[/green]")
                    
                    console.print("\n[dim]Use --detailed flag for full token information[/dim]")
            sys.exit(0)
        else:
            if not quiet:
                console.print("[red]✗ Token expired[/red]")
                if manager.refresh_token:
                    console.print("Run: proxy-client oauth refresh")
                else:
                    console.print("Run: proxy-client oauth login")
            sys.exit(1)
    except Exception as e:
        if not quiet:
            ctx.handle_error(e)
        sys.exit(1)


@oauth_group.command('refresh')
@click.option('--quiet', is_flag=True, help='Quiet mode for scripting')
@click.option('--detailed', '-d', is_flag=True, help='Show detailed token information after refresh')
@click.pass_obj
def oauth_refresh(ctx, quiet, detailed):
    """Refresh OAuth access token using refresh token."""
    try:
        from ..core.auth import TokenManager
        
        manager = TokenManager(ctx.config)
        
        if not manager.refresh_token:
            if not quiet:
                console.print("[red]No refresh token available[/red]")
                console.print("Run: proxy-client oauth login")
            sys.exit(1)
        
        if not quiet:
            console.print("Refreshing OAuth token...")
        
        # Run the async refresh
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            success = loop.run_until_complete(manager.refresh())
        finally:
            loop.close()
        
        if success:
            if not quiet:
                console.print("\n[green]✓ Token refreshed successfully![/green]\n")
                
                if detailed:
                    # Show detailed token information
                    display_token_info(
                        manager.access_token,
                        manager.refresh_token,
                        manager.scope,
                        title="Refreshed OAuth Token"
                    )
                else:
                    remaining = int((manager.expires_at - time.time()) / 60) if manager.expires_at else 30
                    console.print(f"Token valid for: {remaining} minutes")
                
                console.print("\n[green]Token automatically saved to .env[/green]")
            sys.exit(0)
        else:
            if not quiet:
                console.print("[red]✗ Token refresh failed[/red]")
                console.print("Run: proxy-client oauth login --force")
            sys.exit(1)
    except Exception as e:
        if not quiet:
            ctx.handle_error(e)
        sys.exit(1)


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
@click.option('--scope', default='read write', help='OAuth scopes')
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