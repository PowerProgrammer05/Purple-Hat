from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..network.network_tools import PortScannerModule, NetworkReconModule
from ..injection.sqlmap_wrapper import SQLMapWrapper
from ..web_security.web_vulns import XSSModule, CSRFModule, XXEModule, FileUploadModule
from ..injection.sql_injection import SQLInjectionModule
from ..injection.command_injection import CommandInjectionModule
import requests
from urllib.parse import urljoin, urlparse


class AdvancedAutomator:
    def __init__(self, base_dir: str = None):
        self.port_scanner = PortScannerModule()
        self.recon = NetworkReconModule()
        self.sqlmap = SQLMapWrapper(base_dir)
        self.xss = XSSModule()
        self.csrf = CSRFModule()
        self.xxe = XXEModule()
        self.file_upload = FileUploadModule()
        self.sql_inj = SQLInjectionModule()
        self.cmd_inj = CommandInjectionModule()

    def discover_and_test(self, target: str, techniques: List[str] = None, threads: int = 8, timeout: int = 15) -> Dict[str, Any]:
        """Auto-discover endpoints and test without user input per technique"""
        if techniques is None:
            techniques = ['port_scan', 'sql_injection', 'xss', 'command_injection']

        result = {
            'target': target,
            'timestamp': str(__import__('datetime').datetime.utcnow()),
            'results': {}
        }

        if 'port_scan' in techniques:
            result['results']['ports'] = self._auto_port_scan(target, threads)

        if 'sql_injection' in techniques:
            result['results']['sql_injection'] = self._auto_sql_injection(target, timeout)

        if 'xss' in techniques:
            result['results']['xss'] = self._auto_xss(target, threads, timeout)

        if 'command_injection' in techniques:
            result['results']['command_injection'] = self._auto_command_injection(target, timeout)

        if 'csrf' in techniques:
            result['results']['csrf'] = self._auto_csrf(target, timeout)

        if 'xxe' in techniques:
            result['results']['xxe'] = self._auto_xxe(target, timeout)

        return result

    def _auto_port_scan(self, target: str, threads: int) -> Dict[str, Any]:
        """Auto port scan without user input"""
        host = target.split(':')[0].replace('http://', '').replace('https://', '')
        ports = [21,22,23,25,53,80,110,143,443,445,3306,5432,5984,6379,8080,8443,9200,27017]
        results = self.port_scanner.scan_ports_detailed(host, ports, threads=threads)
        open_ports = {p: info for p, info in results.items() if info.get('open')}
        return {'open_ports': open_ports, 'total_scanned': len(ports), 'open_count': len(open_ports)}

    def _auto_sql_injection(self, target: str, timeout: int) -> Dict[str, Any]:
        """Auto SQL injection testing"""
        if not self.sqlmap.is_available():
            return {'error': 'sqlmap not available', 'attempted': False}

        try:
            out = self.sqlmap.run_and_parse(['-u', target, '--batch', '--level=1', '--risk=1'], timeout=timeout)
            return {'sqlmap_result': out, 'status': 'completed'}
        except Exception as e:
            return {'error': str(e), 'status': 'failed'}

    def _auto_xss(self, target: str, threads: int, timeout: int) -> Dict[str, Any]:
        """Auto XSS discovery across common parameters"""
        results = {'vulnerable_params': []}
        common_params = ['q', 'search', 's', 'id', 'name', 'email', 'message', 'comment', 'feedback']

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(self._test_xss_param, target, p): p for p in common_params}
            for fut in as_completed(futures):
                param = futures[fut]
                try:
                    vuln = fut.result()
                    if vuln:
                        results['vulnerable_params'].append({'param': param, 'payloads': vuln})
                except Exception:
                    pass

        return results

    def _test_xss_param(self, target: str, param: str) -> List[str]:
        """Test XSS for a single parameter"""
        vulnerable = []
        for payload in self.xss.generate_payloads()[:5]:
            try:
                r = requests.get(target, params={param: payload}, timeout=8, verify=False)
                if payload in (r.text or ''):
                    vulnerable.append(payload)
            except Exception:
                pass
        return vulnerable

    def _auto_command_injection(self, target: str, timeout: int) -> Dict[str, Any]:
        """Auto command injection testing"""
        results = {'tested': True, 'payloads': []}
        payloads = self.cmd_inj.generate_payloads()[:8]

        for p in payloads:
            try:
                r = requests.get(target, params={'cmd': p}, timeout=timeout, verify=False)
                if any(marker in (r.text or '') for marker in ['root:', 'bin/', 'usr/', 'system']):
                    results['payloads'].append({'payload': p, 'reflected': True})
            except Exception:
                pass

        return results

    def _auto_csrf(self, target: str, timeout: int) -> Dict[str, Any]:
        """Auto CSRF detection"""
        try:
            r = requests.get(target, timeout=timeout, verify=False)
            csrf_checks = self.csrf.check_csrf_protection(r.headers)
            return {'csrf_checks': csrf_checks, 'status': 'completed'}
        except Exception as e:
            return {'error': str(e)}

    def _auto_xxe(self, target: str, timeout: int) -> Dict[str, Any]:
        """Auto XXE testing"""
        results = {'tested': True, 'payloads': []}
        xxe_payloads = self.xxe.generate_payloads()

        for p in xxe_payloads:
            try:
                r = requests.post(target, data=p, timeout=timeout, verify=False)
                if self.xxe.detect_xxe(r.text or ''):
                    results['payloads'].append({'payload': p, 'vulnerable': True})
            except Exception:
                pass

        return results
