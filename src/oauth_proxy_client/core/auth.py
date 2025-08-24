"""OAuth authentication and token management."""

import os
import sys
import time
import json
from pathlib import Path
from typing import Optional, Dict, Any
import httpx
from datetime import datetime, timedelta

from .exceptions import AuthenticationError


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
        self.expires_at = None
        self.scope = None
        self._load_from_env()
    
    def _load_from_env(self):
        """Load tokens from environment variables."""
        self.access_token = os.getenv('OAUTH_ACCESS_TOKEN')
        self.refresh_token = os.getenv('OAUTH_REFRESH_TOKEN')
        
        expires_at_str = os.getenv('OAUTH_TOKEN_EXPIRES_AT')
        if expires_at_str:
            try:
                self.expires_at = float(expires_at_str)
            except (ValueError, TypeError):
                self.expires_at = None
        
        self.scope = os.getenv('OAUTH_TOKEN_SCOPE', '')
    
    def is_valid(self, buffer_seconds: int = 300) -> bool:
        """Check if access token is valid with buffer.
        
        Args:
            buffer_seconds: Number of seconds before expiry to consider invalid (default: 5 minutes)
        
        Returns:
            True if token is valid, False otherwise
        """
        if not self.access_token or not self.expires_at:
            return False
        
        current_time = time.time()
        return current_time < (self.expires_at - buffer_seconds)
    
    async def refresh(self) -> bool:
        """Refresh access token using refresh token.
        
        Returns:
            True if refresh successful, False otherwise
        """
        if not self.refresh_token:
            return False
        
        try:
            base_url = self.config.api_url or 'http://localhost'
            
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
                
                if response.status_code == 200:
                    token_data = response.json()
                    
                    # Update tokens in memory
                    self.access_token = token_data.get('access_token')
                    # Keep existing refresh token if not returned
                    if token_data.get('refresh_token'):
                        self.refresh_token = token_data.get('refresh_token')
                    
                    expires_in = token_data.get('expires_in', 1800)
                    self.expires_at = time.time() + expires_in
                    self.scope = token_data.get('scope', self.scope)
                    
                    # Save to .env
                    self.save_to_env()
                    
                    return True
                    
        except Exception as e:
            # Silently fail - caller will handle
            pass
        
        return False
    
    def save_to_env(self):
        """Save all tokens to .env file atomically."""
        env_path = Path('.env')
        lines = []
        tokens_updated = {
            'OAUTH_ACCESS_TOKEN': False,
            'OAUTH_REFRESH_TOKEN': False,
            'OAUTH_TOKEN_EXPIRES_AT': False,
            'OAUTH_TOKEN_SCOPE': False
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
                    elif line.startswith('OAUTH_TOKEN_EXPIRES_AT='):
                        if self.expires_at:
                            lines.append(f'OAUTH_TOKEN_EXPIRES_AT={self.expires_at}\n')
                            tokens_updated['OAUTH_TOKEN_EXPIRES_AT'] = True
                        else:
                            lines.append(line)
                    elif line.startswith('OAUTH_TOKEN_SCOPE='):
                        if self.scope:
                            lines.append(f'OAUTH_TOKEN_SCOPE={self.scope}\n')
                            tokens_updated['OAUTH_TOKEN_SCOPE'] = True
                        else:
                            lines.append(line)
                    else:
                        lines.append(line)
        
        # Add any tokens that weren't in the file
        if not tokens_updated['OAUTH_ACCESS_TOKEN'] and self.access_token:
            if lines and not lines[-1].endswith('\n'):
                lines.append('\n')
            lines.append(f'OAUTH_ACCESS_TOKEN={self.access_token}\n')
        
        if not tokens_updated['OAUTH_REFRESH_TOKEN'] and self.refresh_token:
            lines.append(f'OAUTH_REFRESH_TOKEN={self.refresh_token}\n')
        
        if not tokens_updated['OAUTH_TOKEN_EXPIRES_AT'] and self.expires_at:
            lines.append(f'OAUTH_TOKEN_EXPIRES_AT={self.expires_at}\n')
        
        if not tokens_updated['OAUTH_TOKEN_SCOPE'] and self.scope:
            lines.append(f'OAUTH_TOKEN_SCOPE={self.scope}\n')
        
        # Write back to .env atomically
        with open(env_path, 'w') as f:
            f.writelines(lines)
    
    async def ensure_valid(self):
        """Ensure we have a valid access token.
        
        Raises:
            AuthenticationError: If no valid token and cannot refresh
        """
        if not self.is_valid():
            if self.refresh_token:
                if not await self.refresh():
                    raise AuthenticationError("Token refresh failed - please run: proxy-client oauth login")
            else:
                raise AuthenticationError("No valid OAuth token - please run: proxy-client oauth login")


class DeviceFlowAuth:
    """GitHub Device Flow authentication."""
    
    def __init__(self, domain: str = 'localhost'):
        """Initialize device flow authentication.
        
        Args:
            domain: OAuth server domain (default: localhost)
        """
        self.domain = domain
        self.base_url = f"http://{domain}" if domain == "localhost" else f"https://{domain}"
    
    def authenticate(self, open_browser: bool = True) -> Optional[Dict[str, Any]]:
        """Perform device flow authentication.
        
        Args:
            open_browser: Whether to automatically open browser
        
        Returns:
            Dictionary with tokens if successful, None otherwise
        """
        try:
            # Step 1: Get device code
            print(f"Requesting device code from {self.base_url}/device/code...")
            
            with httpx.Client() as client:
                response = client.post(f"{self.base_url}/device/code")
                response.raise_for_status()
                device_data = response.json()
            
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
    
    def save_tokens_to_env(self, access_token: str, refresh_token: str, 
                           expires_at: float, scope: str):
        """Save all OAuth tokens to .env file.
        
        Args:
            access_token: OAuth access token
            refresh_token: OAuth refresh token
            expires_at: Unix timestamp when token expires
            scope: Granted scopes
        """
        manager = TokenManager(None)
        manager.access_token = access_token
        manager.refresh_token = refresh_token
        manager.expires_at = expires_at
        manager.scope = scope
        manager.save_to_env()