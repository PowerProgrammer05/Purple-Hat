from typing import List, Dict
import socket


class PortScannerModule:
    def __init__(self):
        self.name = "Port Scanner"
        self.description = "포트 스캔 및 서비스 발견"
    
    def scan_port(self, host: str, port: int, timeout: int = 2) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_common_ports(self, host: str, threads: int = 20) -> Dict[int, bool]:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 5984, 6379, 8080, 8443, 9200, 27017]
        return self.scan_ports_range(host, common_ports, threads=threads)

    def scan_ports_range(self, host: str, ports: List[int], threads: int = 50, timeout: int = 2) -> Dict[int, bool]:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _check(p):
            return p, self.scan_port(host, p, timeout=timeout)

        results: Dict[int, bool] = {}
        with ThreadPoolExecutor(max_workers=min(len(ports), threads)) as ex:
            futures = [ex.submit(_check, p) for p in ports]
            for fut in as_completed(futures):
                try:
                    p, ok = fut.result()
                    results[p] = ok
                except Exception:
                    pass
        return results

    def scan_port_detailed(self, host: str, port: int, timeout: int = 2) -> Dict:
        res = {
            'open': False,
            'banner': '',
            'service': self.get_service_name(port),
        }
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            rc = sock.connect_ex((host, port))
            if rc == 0:
                res['open'] = True
                try:
                    if port in (80, 8080, 8000, 443, 8443):
                        sock.sendall(b"GET / HTTP/1.0\r\nHost: \r\n\r\n")
                    elif port in (21, 22):
                        pass
                    data = sock.recv(2048)
                    res['banner'] = data.decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
            sock.close()
        except Exception:
            pass
        return res

    def scan_ports_detailed(self, host: str, ports: List[int], threads: int = 50, timeout: int = 2) -> Dict[int, Dict]:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _check(p):
            return p, self.scan_port_detailed(host, p, timeout=timeout)

        results: Dict[int, Dict] = {}
        with ThreadPoolExecutor(max_workers=min(len(ports), threads)) as ex:
            futures = [ex.submit(_check, p) for p in ports]
            for fut in as_completed(futures):
                try:
                    p, ok = fut.result()
                    results[p] = ok
                except Exception:
                    pass
        return results
    
    def get_service_name(self, port: int) -> str:
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 5432: "PostgreSQL", 5984: "CouchDB", 6379: "Redis",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
        }
        return services.get(port, "Unknown")


class DNSEnumerationModule:
    def __init__(self):
        self.name = "DNS Enumeration"
        self.description = "DNS 정보 수집"
    
    def resolve_domain(self, domain: str) -> List[str]:
        try:
            import socket
            return socket.gethostbyname_ex(domain)[2]
        except:
            return []
    
    def reverse_dns(self, ip: str) -> str:
        try:
            import socket
            return socket.gethostbyaddr(ip)[0]
        except:
            return "[!] Failed"
    
    def get_dns_records(self, domain: str) -> Dict:
        try:
            import socket
            result = {
                "A": socket.gethostbyname(domain),
                "MX": [],
                "NS": [],
            }
            return result
        except:
            return {}
    
    def subdomain_wordlist(self) -> List[str]:
        return [
            "www", "mail", "ftp", "admin", "test", "dev", "staging",
            "api", "cdn", "img", "images", "static", "assets", "portal",
            "support", "help", "blog", "news", "forum", "chat", "shop",
        ]


class NetworkReconModule:
    def __init__(self):
        self.name = "Network Reconnaissance"
        self.description = "네트워크 정찰"
    
    def whois_info(self, domain: str) -> str:
        return f"WHOIS info for {domain}"
    
    def banner_grabbing(self, host: str, port: int) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner
        except:
            return ""
    
    def get_http_headers(self, host: str) -> Dict:
        return {
            "Server": "Apache/2.4.41",
            "X-Powered-By": "PHP/7.4.3",
            "Set-Cookie": "session=abc123",
        }


class ProxyModule:
    def __init__(self):
        self.name = "Proxy Configuration"
        self.description = "프록시 및 터널링 설정"
    
    def generate_proxy_list(self) -> List[Dict]:
        return [
            {"type": "HTTP", "host": "127.0.0.1", "port": 8080},
            {"type": "SOCKS5", "host": "127.0.0.1", "port": 9050},
        ]
    
    def test_proxy(self, proxy_host: str, proxy_port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((proxy_host, proxy_port))
            sock.close()
            return result == 0
        except:
            return False
