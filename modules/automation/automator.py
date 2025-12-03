from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..network.network_tools import PortScannerModule, NetworkReconModule
from ..injection.sqlmap_wrapper import SQLMapWrapper
from ..web_security.web_vulns import XSSModule


class Automator:
    def __init__(self, base_dir: str = None):
        self.port_scanner = PortScannerModule()
        self.recon = NetworkReconModule()
        self.sqlmap = SQLMapWrapper(base_dir)
        self.xss = XSSModule()

    def fingerprint_and_scan(self, target: str, all_ports: List[int] = None, threads: int = 8) -> Dict[str, Any]:
        out = {
            'target': target,
            'dns': [],
            'ports': {},
            'sqlmap': None,
            'xss_attempts': [],
        }

        try:
            ips = self.recon.banner_grabbing(target, 80) if ':' in target else []
            out['dns'] = ips
        except Exception:
            out['dns'] = []

        ports = all_ports or [21,22,23,25,53,80,110,143,443,445,3306,5432,5984,6379,8080,8443,9200,27017]
        scan_results = self.port_scanner.scan_ports_detailed(target, ports, threads=threads)
        out['ports'] = scan_results

        if self.sqlmap.is_available():
            try:
                r = self.sqlmap.run_and_parse(['-u', target, '--batch', '--level=1', '--risk=1'], timeout=120)
                out['sqlmap'] = r
            except Exception as e:
                out['sqlmap'] = {'error': str(e)}

        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = []
            for payload in self.xss.generate_payloads()[:6]:
                futures.append(ex.submit(self._try_xss, target, payload))
            for fut in as_completed(futures):
                try:
                    out['xss_attempts'].append(fut.result())
                except Exception:
                    pass

        return out

    def _try_xss(self, target: str, payload: str) -> Dict[str, Any]:
        res = {'target': target, 'payload': payload, 'reflected': False, 'details': ''}
        try:
            import requests
            r = requests.get(target, params={'q': payload}, timeout=8, verify=False)
            if payload in (r.text or ''):
                res['reflected'] = True
                res['details'] = 'Reflected in response body'
        except Exception as e:
            res['details'] = str(e)
        return res
