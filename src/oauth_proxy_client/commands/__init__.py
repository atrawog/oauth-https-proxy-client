"""Command modules for OAuth HTTPS Proxy Client."""

# Token commands removed - OAuth only authentication
from .certificates import cert_group
from .proxies import proxy_group
from .routes import route_group
from .services import service_group
from .oauth import oauth_group
from .resources import resource_group
from .logs import log_group
from .system import system_group

__all__ = [
    'cert_group',
    'proxy_group',
    'route_group',
    'service_group',
    'oauth_group',
    'resource_group',
    'log_group',
    'system_group',
]