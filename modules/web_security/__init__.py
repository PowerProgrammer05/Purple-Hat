from .web_vulns import XSSModule, CSRFModule, FileUploadModule, XXEModule
from .security_checks import AuthenticationModule, SSLTLSModule, SecurityHeadersModule

__all__ = [
    'XSSModule',
    'CSRFModule',
    'FileUploadModule',
    'XXEModule',
    'AuthenticationModule',
    'SSLTLSModule',
    'SecurityHeadersModule',
]
