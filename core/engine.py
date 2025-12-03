from modules.injection.sql_injection import SQLInjectionModule
from modules.injection.command_injection import CommandInjectionModule
from modules.injection.ldap_injection import LDAPInjectionModule
from modules.injection.xpath_injection import XPathInjectionModule
from modules.injection.sqlmap_wrapper import SQLMapWrapper
from modules.web_security.web_vulns import XSSModule, CSRFModule, FileUploadModule, XXEModule
from modules.web_security.security_checks import AuthenticationModule, SSLTLSModule, SecurityHeadersModule
from modules.encoding.encoders import EncodingModule
from modules.network.network_tools import PortScannerModule, DNSEnumerationModule, NetworkReconModule, ProxyModule
from modules.automation.automator import Automator


class PurpleHatEngine:
    def __init__(self):
        self.modules = {
            "injection": {
                "sql": SQLInjectionModule(),
                "sqlmap": SQLMapWrapper(),
                "command": CommandInjectionModule(),
                "ldap": LDAPInjectionModule(),
                "xpath": XPathInjectionModule(),
            },
            "web_security": {
                "xss": XSSModule(),
                "csrf": CSRFModule(),
                "file_upload": FileUploadModule(),
                "xxe": XXEModule(),
                "auth": AuthenticationModule(),
                "ssl_tls": SSLTLSModule(),
                "headers": SecurityHeadersModule(),
            },
            "encoding": {
                "encoder": EncodingModule(),
            },
            "network": {
                "scanner": PortScannerModule(),
                "dns": DNSEnumerationModule(),
                "recon": NetworkReconModule(),
                "proxy": ProxyModule(),
            },
            "automation": {
                "automator": Automator()
            }
        }
    
    def get_module(self, category: str, module_name: str):
        return self.modules.get(category, {}).get(module_name)
    
    def list_all_modules(self):
        result = {}
        for category, modules in self.modules.items():
            result[category] = {}
            for name, module in modules.items():
                result[category][name] = {
                    "name": module.name,
                    "description": module.description
                }
        return result
    
    def get_category_modules(self, category: str):
        modules = self.modules.get(category, {})
        return {
            name: {
                "name": module.name,
                "description": module.description
            }
            for name, module in modules.items()
        }
