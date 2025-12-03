"""
Scanning modes configuration for PURPLE HAT
Provides Ready-To-Go and Professional modes
"""

import json
from enum import Enum
from typing import Dict, Any, List
from dataclasses import dataclass, asdict


class ScanMode(Enum):
    """Scanning mode types"""
    READY_TO_GO = "ready_to_go"
    PROFESSIONAL = "professional"


@dataclass
class ScanConfiguration:
    """Configuration for scanning operations"""
    timeout: int = 5
    retries: int = 3
    verify_ssl: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    proxy_enabled: bool = False
    proxy_url: str = "http://127.0.0.1:8080"
    
    # SQL Injection settings
    sql_injection_enabled: bool = True
    sql_injection_methods: List[str] = None
    sql_injection_threads: int = 5
    sql_injection_payloads_limit: int = 100
    
    # XSS settings
    xss_enabled: bool = True
    xss_methods: List[str] = None
    xss_dom_analysis: bool = True
    
    # Command Injection settings
    cmd_injection_enabled: bool = True
    cmd_injection_time_based: bool = True
    cmd_injection_blind: bool = True
    
    # Network scanning
    port_scan_enabled: bool = True
    port_scan_range: str = "1-65535"
    port_scan_timeout: int = 2
    port_scan_threads: int = 50
    
    # Authentication testing
    auth_testing_enabled: bool = True
    auth_common_passwords: bool = True
    auth_brute_force_limit: int = 1000
    
    # SSL/TLS testing
    ssl_test_enabled: bool = True
    ssl_test_old_protocols: bool = True
    ssl_test_weak_ciphers: bool = True
    
    # Output settings
    verbose: bool = False
    save_results: bool = True
    results_format: str = "json"  # json, csv, html, txt
    
    def __post_init__(self):
        if self.sql_injection_methods is None:
            self.sql_injection_methods = ["union", "time_based", "boolean", "error", "stacked"]
        if self.xss_methods is None:
            self.xss_methods = ["reflected", "stored", "dom"]


class ModePresets:
    """Preset configurations for different scanning modes"""
    
    @staticmethod
    def get_ready_to_go() -> ScanConfiguration:
        """Ready-To-Go mode: Automated, comprehensive scanning with sensible defaults"""
        return ScanConfiguration(
            timeout=5,
            retries=2,
            verify_ssl=True,
            proxy_enabled=False,
            
            sql_injection_enabled=True,
            sql_injection_methods=["union", "time_based", "boolean"],
            sql_injection_threads=10,
            sql_injection_payloads_limit=50,
            
            xss_enabled=True,
            xss_methods=["reflected", "stored"],
            xss_dom_analysis=True,
            
            cmd_injection_enabled=True,
            cmd_injection_time_based=True,
            cmd_injection_blind=False,
            
            port_scan_enabled=True,
            port_scan_range="1-1000",  # Common ports only
            port_scan_timeout=2,
            port_scan_threads=100,
            
            auth_testing_enabled=True,
            auth_common_passwords=True,
            auth_brute_force_limit=100,
            
            ssl_test_enabled=True,
            ssl_test_old_protocols=True,
            ssl_test_weak_ciphers=True,
            
            verbose=False,
            save_results=True,
            results_format="json"
        )
    
    @staticmethod
    def get_professional() -> ScanConfiguration:
        """Professional mode: Advanced, customizable scanning with full control"""
        return ScanConfiguration(
            timeout=15,
            retries=5,
            verify_ssl=True,
            proxy_enabled=False,
            
            sql_injection_enabled=True,
            sql_injection_methods=["union", "time_based", "boolean", "error", "stacked"],
            sql_injection_threads=5,
            sql_injection_payloads_limit=500,
            
            xss_enabled=True,
            xss_methods=["reflected", "stored", "dom"],
            xss_dom_analysis=True,
            
            cmd_injection_enabled=True,
            cmd_injection_time_based=True,
            cmd_injection_blind=True,
            
            port_scan_enabled=True,
            port_scan_range="1-65535",  # Full range
            port_scan_timeout=5,
            port_scan_threads=50,
            
            auth_testing_enabled=True,
            auth_common_passwords=True,
            auth_brute_force_limit=5000,
            
            ssl_test_enabled=True,
            ssl_test_old_protocols=True,
            ssl_test_weak_ciphers=True,
            
            verbose=True,
            save_results=True,
            results_format="json"
        )


class ConfigurationManager:
    """Manages scanning configurations and presets"""
    
    def __init__(self):
        self.current_config = ModePresets.get_ready_to_go()
        self.current_mode = ScanMode.READY_TO_GO
    
    def load_ready_to_go(self):
        """Load Ready-To-Go mode"""
        self.current_config = ModePresets.get_ready_to_go()
        self.current_mode = ScanMode.READY_TO_GO
    
    def load_professional(self):
        """Load Professional mode"""
        self.current_config = ModePresets.get_professional()
        self.current_mode = ScanMode.PROFESSIONAL
    
    def update_config(self, **kwargs):
        """Update configuration parameters"""
        for key, value in kwargs.items():
            if hasattr(self.current_config, key):
                setattr(self.current_config, key, value)
    
    def get_config_dict(self) -> Dict[str, Any]:
        """Get current configuration as dictionary"""
        return asdict(self.current_config)
    
    def load_from_file(self, filepath: str):
        """Load configuration from JSON file"""
        try:
            with open(filepath, 'r') as f:
                config_dict = json.load(f)
                for key, value in config_dict.items():
                    if hasattr(self.current_config, key):
                        setattr(self.current_config, key, value)
        except Exception as e:
            print(f"Error loading configuration: {e}")
    
    def save_to_file(self, filepath: str):
        """Save current configuration to JSON file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.get_config_dict(), f, indent=2)
        except Exception as e:
            print(f"Error saving configuration: {e}")
