"""OAuth authentication and token management."""

import os
import sys
import time
import json
from pathlib import Path
from typing import Optional, Dict, Any
import httpx
from datetime import datetime, timedelta
from typing import List

from .exceptions import AuthenticationError
from .logging import get_logger

# Get logger for this module
logger = get_logger('auth')


class TokenManager:
    """Manages OAuth tokens with automatic validation and renewal."""
    
    def __init__(self, config):
        """Initialize token manager with configuration.
        
        Args:
            config: Configuration object with API settings
        """
        self.config = config
        self.access_token = None
        self.refresh_token = None
        self._load_from_env()
    
    def _load_from_env(self):
        """Load tokens from environment variables."""
        # Get tokens, treating empty strings as None
        access_token = os.getenv('OAUTH_ACCESS_TOKEN', '').strip()
        refresh_token = os.getenv('OAUTH_REFRESH_TOKEN', '').strip()
        
        self.access_token = access_token if access_token else None
        self.refresh_token = refresh_token if refresh_token else None
        
        # Log at TRACE level
        if self.access_token:
            logger.trace(f"OAUTH_ACCESS_TOKEN loaded from environment (length: {len(self.access_token)})")
        else:
            logger.trace("OAUTH_ACCESS_TOKEN not found in environment")
        
        if self.refresh_token:
            logger.trace(f"OAUTH_REFRESH_TOKEN loaded from environment (length: {len(self.refresh_token)})")
        else:
            logger.trace("OAUTH_REFRESH_TOKEN not found in environment")
    
    async def validate_with_server(self) -> bool:
        """Validate token with OAuth server using introspection endpoint.
        
        Returns:
            True if token is active, False otherwise
        """
        if not self.access_token:
            logger.trace("No access token to validate")
            return False
        
        base_url = self.config.api_url or 'http://localhost'
        logger.trace(f"Validating token with {base_url}/introspect")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{base_url}/introspect",
                    data={
                        'token': self.access_token,
                        'token_type_hint': 'access_token',
                        'client_id': 'device_flow_client'  # Required for introspection
                    },
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    is_active = result.get('active', False)
                    
                    if is_active:
                        logger.trace(f"Token is active (scope: {result.get('scope', 'unknown')})")
                    else:
                        logger.trace("Token is not active")
                    
                    return is_active
                else:
                    logger.warning(f"Token introspection failed: HTTP {response.status_code}")
                    return False
                    
        except httpx.ConnectError as e:
            logger.warning(f"Cannot connect to {base_url} for validation: {e}")
            # Fall back to local JWT validation
            return self.is_valid()
        except httpx.TimeoutException:
            logger.warning("Token validation timed out, using local validation")
            return self.is_valid()
        except Exception as e:
            logger.error(f"Token validation error: {type(e).__name__}: {e}")
            return False
    
    def is_valid(self, buffer_seconds: int = 300) -> bool:
        """Check if access token is valid locally (fallback when server unavailable).
        
        Args:
            buffer_seconds: Number of seconds before expiry to consider invalid (default: 5 minutes)
        
        Returns:
            True if token is valid, False otherwise
        """
        if not self.access_token:
            return False
        
        try:
            import jwt
            claims = jwt.decode(self.access_token, options={"verify_signature": False})
            
            if 'exp' not in claims:
                logger.trace("Token has no expiration claim")
                return False
            
            current_time = time.time()
            expires_at = claims['exp']
            time_left = expires_at - current_time
            
            if time_left < buffer_seconds:
                logger.trace(f"Token expires in {int(time_left)}s (less than {buffer_seconds}s buffer)")
                return False
            
            logger.trace(f"Token valid for {int(time_left)}s")
            return True
            
        except jwt.DecodeError as e:
            logger.error(f"Invalid JWT format: {e}")
            return False
        except Exception as e:
            logger.error(f"JWT validation error: {type(e).__name__}: {e}")
            return False
    
    async def refresh(self) -> bool:
        """Refresh access token using refresh token.
        
        Returns:
            True if refresh successful, False otherwise
        """
        if not self.refresh_token:
            logger.info("No refresh token available for token refresh")
            return False
        
        base_url = self.config.api_url or 'http://localhost'
        logger.trace(f"Refreshing token at {base_url}/token")
        logger.trace(f"Using refresh_token: {self.refresh_token[:10]}..." if len(self.refresh_token) > 10 else "Using refresh_token")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{base_url}/token",
                    data={
                        'grant_type': 'refresh_token',
                        'refresh_token': self.refresh_token,
                        'client_id': 'device_flow_client'
                    },
                    timeout=30.0
                )
                
                logger.trace(f"Token refresh response: HTTP {response.status_code}")
                
                if response.status_code == 200:
                    token_data = response.json()
                    self.access_token = token_data.get('access_token')
                    
                    if token_data.get('refresh_token'):
                        self.refresh_token = token_data.get('refresh_token')
                        logger.trace("New refresh token received")
                    
                    self.save_to_env()
                    logger.info("Token refreshed successfully")
                    return True
                
                # Log specific OAuth errors
                try:
                    error_data = response.json()
                    error = error_data.get('error', 'unknown_error')
                    desc = error_data.get('error_description', '')
                    
                    if error == 'invalid_grant':
                        logger.error(f"Refresh token is invalid or expired: {desc}")
                    elif error == 'invalid_client':
                        logger.error(f"Client authentication failed: {desc}")
                    else:
                        logger.error(f"OAuth error '{error}': {desc}")
                except:
                    logger.error(f"Token refresh failed: HTTP {response.status_code}")
                    if response.text:
                        logger.trace(f"Response body: {response.text[:500]}")
                
                return False
                
        except httpx.ConnectError as e:
            logger.error(f"Cannot connect to {base_url}: {e}")
            return False
        except httpx.TimeoutException:
            logger.error("Token refresh timed out after 30 seconds")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during refresh: {type(e).__name__}: {e}")
            logger.trace("Full traceback:", exc_info=True)
            return False
    
    def save_to_env(self):
        """Save OAuth tokens to .env file atomically (only access and refresh tokens)."""
        env_path = Path('.env')
        lines = []
        tokens_updated = {
            'OAUTH_ACCESS_TOKEN': False,
            'OAUTH_REFRESH_TOKEN': False
        }
        
        # Read existing .env if it exists
        if env_path.exists():
            with open(env_path, 'r') as f:
                for line in f:
                    # Check if this is one of our token lines
                    if line.startswith('OAUTH_ACCESS_TOKEN='):
                        if self.access_token:
                            lines.append(f'OAUTH_ACCESS_TOKEN={self.access_token}\n')
                            tokens_updated['OAUTH_ACCESS_TOKEN'] = True
                        else:
                            lines.append(line)  # Keep existing if we don't have new
                    elif line.startswith('OAUTH_REFRESH_TOKEN='):
                        if self.refresh_token:
                            lines.append(f'OAUTH_REFRESH_TOKEN={self.refresh_token}\n')
                            tokens_updated['OAUTH_REFRESH_TOKEN'] = True
                        else:
                            lines.append(line)
                    elif line.startswith('OAUTH_TOKEN_EXPIRES_AT=') or line.startswith('OAUTH_TOKEN_SCOPE='):
                        # Skip deprecated fields entirely
                        continue
                    else:
                        lines.append(line)
        
        # Add any tokens that weren't in the file
        if not tokens_updated['OAUTH_ACCESS_TOKEN'] and self.access_token:
            if lines and not lines[-1].endswith('\n'):
                lines.append('\n')
            lines.append(f'OAUTH_ACCESS_TOKEN={self.access_token}\n')
        
        if not tokens_updated['OAUTH_REFRESH_TOKEN'] and self.refresh_token:
            lines.append(f'OAUTH_REFRESH_TOKEN={self.refresh_token}\n')
        
        # Write back to .env atomically
        with open(env_path, 'w') as f:
            f.writelines(lines)
    
    async def ensure_valid(self, use_server_validation: bool = True):
        """Ensure we have a valid access token.
        
        Args:
            use_server_validation: If True, validate with server first
            
        Raises:
            AuthenticationError: If no valid token and cannot refresh
        """
        # Try server validation first if enabled
        if use_server_validation:
            if await self.validate_with_server():
                return
        elif self.is_valid():
            return
        
        # Token is invalid or missing
        if not self.access_token:
            if not self.refresh_token:
                logger.info("No OAuth tokens found - need to authenticate")
                raise AuthenticationError("No OAuth tokens available")
            
            logger.info("No access token, attempting refresh")
            if not await self.refresh():
                raise AuthenticationError("Failed to obtain access token using refresh token")
        else:
            # Have access token but it's invalid
            if not self.refresh_token:
                logger.info("Access token invalid and no refresh token available")
                raise AuthenticationError("Token invalid and no refresh token available")
            
            logger.info("Access token invalid, attempting refresh")
            if not await self.refresh():
                raise AuthenticationError("Failed to refresh invalid token")


class DeviceFlowAuth:
    """GitHub Device Flow authentication."""
    
    def __init__(self, domain: str = 'localhost'):
        """Initialize device flow authentication.
        
        Args:
            domain: OAuth server domain (default: localhost)
        """
        self.domain = domain
        # Use the domain as provided - don't tamper with it
        if domain == "localhost":
            self.base_url = "http://localhost"
        else:
            self.base_url = f"https://{domain}"
    
    
    def authenticate(self, open_browser: bool = True) -> Optional[Dict[str, Any]]:
        """OAuth 2.0 Device Flow with CLIENT-DRIVEN resource discovery.
        
        RFC 8628 (Device Flow) + RFC 8707 (Resource Indicators) compliant.
        The CLIENT determines what resources to request.
        
        Args:
            open_browser: Whether to automatically open browser
        
        Returns:
            Dictionary with tokens if successful, None otherwise
        """
        try:
            # Step 1: CLIENT determines required resources
            resources = self._determine_required_resources()
            
            # Step 2: Request device code with explicit resources
            print(f"Requesting device code from {self.base_url}/device/code...")
            device_data = self._request_device_code(resources)
            
            if not device_data:
                return None
            
            device_code = device_data.get("device_code")
            user_code = device_data.get("user_code")
            verification_uri = device_data.get("verification_uri")
            expires_in = device_data.get("expires_in", 900)
            interval = device_data.get("interval", 5)
            
            if not all([device_code, user_code, verification_uri]):
                print("Invalid response from device/code endpoint")
                return None
            
            # Step 2: Show user the code and URL
            print(f"\n{'='*50}")
            print(f"Please visit: {verification_uri}")
            print(f"And enter code: {user_code}")
            print(f"{'='*50}\n")
            
            if open_browser:
                try:
                    import webbrowser
                    webbrowser.open(verification_uri)
                    print("Browser opened automatically.")
                except:
                    print("Could not open browser automatically.")
            
            print(f"Waiting for authorization (expires in {expires_in} seconds)...")
            
            # Step 3: Poll for token
            start_time = time.time()
            while time.time() - start_time < expires_in:
                time.sleep(interval)
                
                try:
                    with httpx.Client() as client:
                        response = client.post(
                            f"{self.base_url}/device/token",
                            data={
                                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                "device_code": device_code,
                                "client_id": "device_flow_client"
                            }
                        )
                        
                        if response.status_code == 200:
                            token_data = response.json()
                            access_token = token_data.get("access_token")
                            refresh_token = token_data.get("refresh_token")
                            scope = token_data.get("scope", "")
                            expires_in = token_data.get("expires_in", 1800)
                            
                            print(f"\n✓ Authentication successful!")
                            
                            return {
                                'access_token': access_token,
                                'refresh_token': refresh_token,
                                'expires_at': time.time() + expires_in,
                                'scope': scope
                            }
                        
                        elif response.status_code == 400:
                            error_data = response.json()
                            error = error_data.get("error")
                            
                            if error == "authorization_pending":
                                # User hasn't authorized yet
                                print(".", end="", flush=True)
                            elif error == "slow_down":
                                # Polling too fast
                                interval = error_data.get("interval", interval + 5)
                            elif error == "expired_token":
                                print("\n✗ Device code expired. Please try again.")
                                return None
                            elif error == "access_denied":
                                print("\n✗ Access denied by user.")
                                return None
                            else:
                                print(f"\n✗ Error: {error}")
                                return None
                except Exception as e:
                    # Continue polling on network errors
                    pass
            
            print("\n✗ Authentication timed out.")
            return None
            
        except Exception as e:
            print(f"Error during authentication: {e}")
            return None
    
    def _determine_required_resources(self) -> List[str]:
        """CLIENT business logic to determine required resources.
        
        This is APPLICATION logic, not OAuth protocol.
        The client decides based on its capabilities and needs.
        """
        existing_token = os.getenv('OAUTH_ACCESS_TOKEN', '').strip()
        
        # If no token or expired, bootstrap with localhost
        if not existing_token or self._is_token_expired(existing_token):
            print("Bootstrap: Requesting access to localhost only")
            return ["http://localhost"]
        
        # Have token, try to discover all available proxies
        print("Discovering available auth-enabled proxies...")
        try:
            proxies = self._discover_available_proxies(existing_token)
            resources = self._build_resource_list(proxies)
            print(f"Requesting access to {len(resources)} resources:")
            for r in resources:
                print(f"  - {r}")
            return resources
        except Exception as e:
            print(f"Discovery failed ({e}), requesting localhost only")
            return ["http://localhost"]
    
    def _discover_available_proxies(self, token: str) -> List[Dict[str, Any]]:
        """Use API to discover available proxies.
        
        This is APPLICATION-SPECIFIC logic, not OAuth.
        """
        with httpx.Client(timeout=10.0) as client:
            response = client.get(
                f"{self.base_url}/proxy/targets/",
                headers={"Authorization": f"Bearer {token}"},
                params={"auth_enabled": "true"}
            )
            
            if response.status_code == 401:
                # Token invalid/expired
                raise Exception("Token invalid or expired")
            
            response.raise_for_status()
            return response.json()
    
    def _build_resource_list(self, proxies: List[Dict[str, Any]]) -> List[str]:
        """Convert proxy list to OAuth resource URIs.
        
        OAuth resources are URIs that identify protected resources.
        """
        resources = []
        
        for proxy in proxies:
            if not proxy.get("auth_enabled"):
                continue
                
            hostname = proxy.get("proxy_hostname")
            if not hostname:
                continue
                
            # Build proper resource URI
            if hostname == "localhost":
                resources.append("http://localhost")
            else:
                resources.append(f"https://{hostname}")
        
        # Ensure localhost is first (if present) for consistency
        if "http://localhost" in resources:
            resources.remove("http://localhost")
            resources.insert(0, "http://localhost")
        
        return resources if resources else ["http://localhost"]
    
    def _request_device_code(self, resources: List[str]) -> Optional[Dict[str, Any]]:
        """Request device code with explicit resources per RFC 8707.
        
        RFC 8707 Section 2: Resource parameter(s) in authorization request.
        Multiple resources sent as repeated form parameters.
        """
        with httpx.Client(timeout=30.0) as client:
            # Build form data with repeated resource parameters
            # httpx expects data as dict for form encoding, with list values for repeated params
            form_data = {
                "client_id": "device_flow_client",
                "scope": "read:user user:email",
            }
            
            # Add resources as a list - httpx will handle repeated parameters
            if resources:
                form_data["resource"] = resources
            
            response = client.post(
                f"{self.base_url}/device/code",
                data=form_data
            )
            
            if response.status_code != 200:
                print(f"Failed to get device code: {response.status_code}")
                print(response.text)
                return None
            
            return response.json()
    
    def _is_token_expired(self, token: str) -> bool:
        """Check if JWT token is expired."""
        try:
            import jwt
            # Decode without verification to check expiry
            payload = jwt.decode(token, options={"verify_signature": False})
            exp = payload.get("exp", 0)
            # Add 60 second buffer for clock skew
            return time.time() >= (exp - 60)
        except Exception:
            # Treat any decode error as expired
            return True
    
    def save_tokens_to_env(self, access_token: str, refresh_token: str, 
                           expires_at: float = None, scope: str = None):
        """Save OAuth tokens to .env file.
        
        Args:
            access_token: OAuth access token
            refresh_token: OAuth refresh token
            expires_at: Deprecated, ignored
            scope: Deprecated, ignored
        """
        manager = TokenManager(None)
        manager.access_token = access_token
        manager.refresh_token = refresh_token
        manager.save_to_env()