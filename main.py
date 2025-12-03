import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import PurpleHatEngine
from ui import UIRenderer, MenuSystem, Menu, HelpSystem
from ui.renderer import Symbol, Color
from modules.injection.sql_injection import SQLInjectionModule
from modules.injection.command_injection import CommandInjectionModule
from modules.injection.ldap_injection import LDAPInjectionModule
from modules.injection.xpath_injection import XPathInjectionModule
from modules.injection.sqlmap_wrapper import SQLMapWrapper
from modules.web_security.web_vulns import XSSModule, CSRFModule, FileUploadModule, XXEModule
from modules.web_security.security_checks import AuthenticationModule, SSLTLSModule, SecurityHeadersModule
from modules.encoding.encoders import EncodingModule
from modules.network.network_tools import PortScannerModule, DNSEnumerationModule, NetworkReconModule, ProxyModule
from utils.advanced import ReportGenerator, PayloadValidator, SessionManager, StatisticsTracker
from utils.payloads_db import PAYLOADS_DATABASE, COMMON_PORTS


class PurpleHatApplication:
    def __init__(self):
        self.engine = PurpleHatEngine()
        self.renderer = UIRenderer()
        self.menu_system = MenuSystem(self.renderer)
        self.help_system = HelpSystem(self.renderer)
        self.report_gen = ReportGenerator()
        self.session_mgr = SessionManager()
        self.stats = StatisticsTracker()
        
        self.sql_module = SQLInjectionModule()
        self.cmd_module = CommandInjectionModule()
        self.ldap_module = LDAPInjectionModule()
        self.xpath_module = XPathInjectionModule()
        self.sqlmap = SQLMapWrapper()
        self.xss_module = XSSModule()
        self.csrf_module = CSRFModule()
        self.fileupload_module = FileUploadModule()
        self.xxe_module = XXEModule()
        self.auth_module = AuthenticationModule()
        self.ssl_module = SSLTLSModule()
        self.headers_module = SecurityHeadersModule()
        self.encoding_module = EncodingModule()
        self.port_scanner = PortScannerModule()
        self.dns_enum = DNSEnumerationModule()
        self.network_recon = NetworkReconModule()
    
    def run(self):
        self.renderer.clear_screen()
        self.renderer.print_banner()
        self.main_menu()
    
    def main_menu(self):
        while True:
            main = self.menu_system.create_menu("PURPLE HAT - Main Menu")
            
            main.add_option(
                "Injection Testing",
                self.injection_menu,
                "SQL, Command, LDAP, XPath 주입"
            )
            
            main.add_option(
                "Web Security",
                self.web_security_menu,
                "XSS, CSRF, 파일 업로드 등"
            )
            
            main.add_option(
                "Encoding/Decoding",
                self.encoding_menu,
                "다양한 인코딩 도구"
            )
            
            main.add_option(
                "Network Tools",
                self.network_menu,
                "포트 스캔, DNS, 정찰"
            )
            
            main.add_option(
                "Statistics",
                self.show_statistics,
                "통계 및 사용 현황"
            )
            main.add_option(
                "Findings & Reports",
                self.show_findings,
                "발견사항 보기 및 보고서 내보내기"
            )
            
            main.add_option(
                "Help",
                self.show_help,
                "도움말 및 기법 설명"
            )
            
            result = self.menu_system.show_menu(main)
            if not result:
                self.show_exit_menu()
                break
    
    def show_exit_menu(self):
        self.renderer.print_section("프로그램 종료")
        self.renderer.print_info("보고서를 저장하시겠습니까?")
        
        choice = self.renderer.input_choice("선택 (Y/N)")
        
        if choice.lower() == 'y':
            filename = self.renderer.input_prompt("보고서 파일명 입력 (확장자 제외)")
            self.report_gen.generate_json_report(f"{filename}.json")
            self.report_gen.generate_text_report(f"{filename}.txt")
            self.renderer.print_success(f"보고서 저장 완료: {filename}.*")
        
        self.renderer.print_section("PURPLE HAT을 사용해주셔서 감사합니다!")
        self.renderer.print_info(f"총 생성된 페이로드: {self.stats.get_stats()['payloads_generated']}")
        self.renderer.print_info(f"총 스캔 수행: {self.stats.get_stats()['scans_performed']}")
    
    def injection_menu(self):
        menu = self.menu_system.create_menu("SQL Injection Testing")
        
        menu.add_option(
            "Generate SQL Payloads",
            self.sql_payloads_menu,
            "다양한 SQL 주입 페이로드 생성"
        )
        
        menu.add_option(
            "Command Injection",
            self.command_injection_menu,
            "명령어 주입 페이로드"
        )
        
        menu.add_option(
            "LDAP Injection",
            self.ldap_injection_menu,
            "LDAP 주입 테스트"
        )
        
        menu.add_option(
            "XPath Injection",
            self.xpath_injection_menu,
            "XPath 주입 테스트"
        )
        
        menu.add_option(
            "sqlmap (local)",
            self.sqlmap_menu,
            "로컬 sqlmap을 이용한 강력한 SQL 검사"
        )
        
        self.menu_system.show_menu(menu)
    
    def sql_payloads_menu(self):
        techniques = {
            "union": "Union-based 기법",
            "time_based": "Time-based 기법",
            "boolean": "Boolean-based 기법",
            "error_based": "Error-based 기법",
        }
        
        menu = self.menu_system.create_menu("SQL Injection Techniques")
        
        for tech, desc in techniques.items():
            menu.add_option(
                f"{tech.replace('_', ' ').title()}",
                lambda t=tech: self.display_payloads("sql", t),
                desc
            )
        
        menu.add_option(
            "Encode Payload",
            self.encode_sql_payload,
            "페이로드 인코딩"
        )
        
        menu.add_option(
            "Tamper Payload",
            self.tamper_sql_payload,
            "페이로드 변형"
        )
        
        self.menu_system.show_menu(menu)
    
    def display_payloads(self, injection_type: str, technique: str = None):
        if injection_type == "sql" and technique:
            payloads = PAYLOADS_DATABASE.get("sql_injection", {}).get(technique, [])
            title = f"SQL Injection - {technique.replace('_', ' ').title()}"
        else:
            payloads = []
            title = "Payloads"
        
        self.renderer.print_section(title)
        
        for idx, payload in enumerate(payloads, 1):
            display_text = payload[:70] + "..." if len(payload) > 70 else payload
            self.renderer.print_option(idx, display_text)
        
        choice = self.renderer.input_choice("페이로드 선택")
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(payloads):
                selected = payloads[choice_num - 1]
                self.copy_to_clipboard(selected)
                self.renderer.print_success(f"클립보드에 복사됨")
                self.stats.increment_stat("payloads_used")
                self.report_gen.add_finding(injection_type, technique, selected, "copied")
        except ValueError:
            self.renderer.print_error("잘못된 선택입니다.")
    
    def encode_sql_payload(self):
        payload = self.renderer.input_prompt("인코딩할 페이로드 입력")
        
        encodings = ["url", "double_url", "unicode", "hex", "base64"]
        
        menu = self.menu_system.create_menu("Select Encoding")
        for enc in encodings:
            menu.add_option(
                enc.upper(),
                lambda e=enc: self.display_encoded_payload(payload, e),
                f"{enc} 인코딩"
            )
        
        self.menu_system.show_menu(menu)
    
    def display_encoded_payload(self, payload: str, encoding: str):
        encoded = self.sql_module.encode_payload(payload, encoding)
        self.renderer.print_result_box(
            f"Encoded Payload ({encoding.upper()})",
            encoded
        )
        self.copy_to_clipboard(encoded)
        self.renderer.print_success("클립보드에 복사됨")
    
    def tamper_sql_payload(self):
        payload = self.renderer.input_prompt("변형할 페이로드 입력")
        
        techniques = ["comment", "space_replace", "case", "char_encode"]
        
        menu = self.menu_system.create_menu("Select Tamper Technique")
        for tech in techniques:
            menu.add_option(
                tech.replace('_', ' ').title(),
                lambda t=tech: self.display_tampered_payload(payload, t),
                f"{tech} 기법"
            )
        
        self.menu_system.show_menu(menu)
    
    def display_tampered_payload(self, payload: str, technique: str):
        tampered = self.sql_module.tamper_payload(payload, technique)
        self.renderer.print_result_box(
            f"Tampered Payload ({technique})",
            tampered
        )
        self.copy_to_clipboard(tampered)
        self.renderer.print_success("클립보드에 복사됨")
    
    def command_injection_menu(self):
        self.renderer.print_section("Command Injection Payloads")
        payloads = PAYLOADS_DATABASE.get("command_injection", [])
        
        for idx, payload in enumerate(payloads, 1):
            self.renderer.print_option(idx, payload)
        
        choice = self.renderer.input_choice("페이로드 선택")
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(payloads):
                self.copy_to_clipboard(payloads[choice_num - 1])
                self.renderer.print_success("클립보드에 복사됨")
                self.stats.increment_stat("payloads_used")
        except ValueError:
            pass
    
    def ldap_injection_menu(self):
        self.renderer.print_section("LDAP Injection Payloads")
        payloads = PAYLOADS_DATABASE.get("ldap_injection", [])
        
        for idx, payload in enumerate(payloads, 1):
            self.renderer.print_option(idx, payload)
        
        choice = self.renderer.input_choice("페이로드 선택")
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(payloads):
                self.copy_to_clipboard(payloads[choice_num - 1])
                self.renderer.print_success("클립보드에 복사됨")
                self.stats.increment_stat("payloads_used")
        except ValueError:
            pass
    
    def xpath_injection_menu(self):
        self.renderer.print_section("XPath Injection Payloads")
        payloads = PAYLOADS_DATABASE.get("xpath_injection", [])
        
        for idx, payload in enumerate(payloads, 1):
            self.renderer.print_option(idx, payload)
        
        choice = self.renderer.input_choice("페이로드 선택")
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(payloads):
                self.copy_to_clipboard(payloads[choice_num - 1])
                self.renderer.print_success("클립보드에 복사됨")
                self.stats.increment_stat("payloads_used")
        except ValueError:
            pass
    
    def web_security_menu(self):
        menu = self.menu_system.create_menu("Web Security Testing")
        
        menu.add_option(
            "XSS Testing",
            self.xss_menu,
            "Cross-Site Scripting 테스트"
        )
        
        menu.add_option(
            "CSRF Testing",
            self.csrf_menu,
            "Cross-Site Request Forgery 테스트"
        )
        
        menu.add_option(
            "File Upload",
            self.fileupload_menu,
            "파일 업로드 취약점"
        )
        
        menu.add_option(
            "XXE Testing",
            self.xxe_menu,
            "XML External Entity 테스트"
        )
        
        menu.add_option(
            "Authentication",
            self.auth_menu,
            "인증 메커니즘 테스트"
        )
        
        menu.add_option(
            "SSL/TLS",
            self.ssl_menu,
            "SSL/TLS 구성 점검"
        )
        
        menu.add_option(
            "Security Headers",
            self.headers_menu,
            "보안 헤더 점검"
        )
        
        self.menu_system.show_menu(menu)
    
    def xss_menu(self):
        menu = self.menu_system.create_menu("XSS Testing")
        
        menu.add_option(
            "Basic Payloads",
            self.display_xss_basic,
            "기본 XSS 페이로드"
        )
        
        menu.add_option(
            "Advanced Payloads",
            self.display_xss_advanced,
            "고급 XSS 페이로드"
        )
        
        self.menu_system.show_menu(menu)
    
    def display_xss_basic(self):
        self.renderer.print_section("XSS - Basic Payloads")
        payloads = PAYLOADS_DATABASE.get("xss", {}).get("basic", [])
        
        for idx, payload in enumerate(payloads, 1):
            display_text = payload[:60] + "..." if len(payload) > 60 else payload
            self.renderer.print_option(idx, display_text)
        
        choice = self.renderer.input_choice("페이로드 선택")
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(payloads):
                self.copy_to_clipboard(payloads[choice_num - 1])
                self.renderer.print_success("클립보드에 복사됨")
                self.stats.increment_stat("payloads_used")
        except ValueError:
            pass
    
    def display_xss_advanced(self):
        self.renderer.print_section("XSS - Advanced Payloads")
        payloads = PAYLOADS_DATABASE.get("xss", {}).get("advanced", [])
        
        for idx, payload in enumerate(payloads, 1):
            display_text = payload[:60] + "..." if len(payload) > 60 else payload
            self.renderer.print_option(idx, display_text)
        
        choice = self.renderer.input_choice("페이로드 선택")
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(payloads):
                self.copy_to_clipboard(payloads[choice_num - 1])
                self.renderer.print_success("클립보드에 복사됨")
                self.stats.increment_stat("payloads_used")
        except ValueError:
            pass
    
    def csrf_menu(self):
        self.renderer.print_section("CSRF Testing")
        target_url = self.renderer.input_prompt("Target URL입력")
        
        method = self.renderer.input_prompt("HTTP Method (POST/GET)", "POST")
        
        params_input = self.renderer.input_prompt("Parameters (key=value, 쉼표로 구분)")
        
        params = {}
        for param in params_input.split(','):
            if '=' in param:
                k, v = param.split('=', 1)
                params[k.strip()] = v.strip()
        
        csrf_html = self.csrf_module.generate_csrf_html(target_url, method, params)
        
        self.renderer.print_result_box("CSRF HTML", csrf_html)
        self.copy_to_clipboard(csrf_html)
        self.renderer.print_success("CSRF HTML 클립보드에 복사됨")
    
    def fileupload_menu(self):
        menu = self.menu_system.create_menu("File Upload Testing")
        
        menu.add_option(
            "Malicious Filenames",
            self.show_malicious_filenames,
            "악의적인 파일명"
        )
        
        menu.add_option(
            "PHP Shells",
            self.show_php_shells,
            "PHP 웹쉘"
        )
        
        self.menu_system.show_menu(menu)
    
    def show_malicious_filenames(self):
        self.renderer.print_section("Malicious Filenames")
        filenames = PAYLOADS_DATABASE.get("file_upload", {}).get("bypass_techniques", [])
        
        for idx, filename in enumerate(filenames, 1):
            self.renderer.print_option(idx, filename)
        
        choice = self.renderer.input_choice("파일명 선택")
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(filenames):
                self.copy_to_clipboard(filenames[choice_num - 1])
                self.renderer.print_success("파일명 클립보드에 복사됨")
                self.stats.increment_stat("payloads_used")
        except ValueError:
            pass
    
    def show_php_shells(self):
        self.renderer.print_section("PHP Shells")
        shells = self.fileupload_module.generate_php_shells()
        
        for idx, shell in enumerate(shells, 1):
            self.renderer.print_option(idx, shell[:50] + "..." if len(shell) > 50 else shell)
        
        choice = self.renderer.input_choice("셸 선택")
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(shells):
                self.copy_to_clipboard(shells[choice_num - 1])
                self.renderer.print_success("셸 클립보드에 복사됨")
        except ValueError:
            pass
    
    def xxe_menu(self):
        self.renderer.print_section("XXE Payloads")
        payloads = PAYLOADS_DATABASE.get("xxe", [])
        
        for idx, payload in enumerate(payloads, 1):
            self.renderer.print_option(idx, f"Payload {idx}")
        
        choice = self.renderer.input_choice("페이로드 선택")
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(payloads):
                self.renderer.print_result_box("XXE Payload", payloads[choice_num - 1])
                self.copy_to_clipboard(payloads[choice_num - 1])
                self.renderer.print_success("페이로드 클립보드에 복사됨")
                self.stats.increment_stat("payloads_used")
        except ValueError:
            pass

    def sqlmap_menu(self):
        menu = self.menu_system.create_menu("sqlmap - Local Integration")
        menu.add_option("Show sqlmap path", self.sqlmap_show_path, "현재 sqlmap 경로 표시")
        menu.add_option("Set sqlmap path", self.sqlmap_set_path, "로컬 sqlmap 경로 설정")
        if not self.sqlmap.is_available():
            menu.add_option("Attempt to locate sqlmap again", self.sqlmap_refresh, "감지 재시도")
            menu.add_option("Cancel / Back", lambda: None, "뒤로")
            self.menu_system.show_menu(menu)
            return

        menu = self.menu_system.create_menu("sqlmap - Local Integration")
        menu.add_option("Quick Scan (level=1,risk=1)", self.sqlmap_quick_scan, "빠른 스캔")
        menu.add_option("Fingerprint", self.sqlmap_fingerprint, "DB fingerprint")
        menu.add_option("Dump Database/Table", self.sqlmap_dump_menu, "데이터베이스/테이블 덤프")
        menu.add_option("Custom Args", self.sqlmap_custom_menu, "사용자 인자 전달")
        menu.add_option("Quick Scan (parsed)", self.sqlmap_quick_scan_parsed, "빠른 스캔 + 결과 파싱")
        menu.add_option("Batch Quick Scan (targets list)", self.sqlmap_batch_scan, "파일/쉼표 분리 타깃 여러개")
        menu.add_option("Batch Quick Scan (parallel)", self.sqlmap_batch_scan_parallel, "병렬 배치 스캔")
        self.menu_system.show_menu(menu)

    def sqlmap_quick_scan(self):
        target = self.renderer.input_prompt("타깃 URL 또는 --data 문자열 입력")
        self.renderer.print_loading("sqlmap quick scan")
        out = self.sqlmap.quick_scan(target)
        if out.get('error'):
            self.renderer.print_error(out.get('error'))
        else:
            txt = out.get('stdout', '')[:4000]
            self.renderer.print_result_box("sqlmap Quick Scan Output", txt)
            self.report_gen.add_structured_finding('sqlmap', 'quick_scan', target, 'completed', metadata={}, raw_output=txt)
            self.stats.increment_stat('scans_performed')

    def sqlmap_quick_scan_parsed(self):
        target = self.renderer.input_prompt("타깃 URL 또는 --data 문자열 입력")
        self.renderer.print_loading("sqlmap quick scan (parsed)")
        out = self.sqlmap.run_and_parse(['-u', target, '--batch', '--level=1', '--risk=1'])
        if out.get('error'):
            self.renderer.print_error(out.get('error'))
            return
        raw = out.get('raw', {})
        parsed = out.get('parsed', {})
        txt = raw.get('stdout', '')[:4000]
        self.renderer.print_result_box("sqlmap Quick Scan (parsed)", txt)
        details = []
        if parsed.get('issues'):
            details.append(f"issues={len(parsed['issues'])}")
            for i in parsed['issues'][:3]:
                details.append(i)
        if parsed.get('databases'):
            details.append(f"databases={len(parsed['databases'])}")
            details += parsed['databases'][:3]
        detail_str = '\n'.join(details)[:200]
        self.report_gen.add_structured_finding('sqlmap', 'quick_scan_parsed', target, 'completed', metadata={'summary': detail_str, 'issues': parsed.get('issues', []), 'databases': parsed.get('databases', [])}, raw_output=txt)
        self.stats.increment_stat('scans_performed')
        self.stats.increment_stat('findings', len(parsed.get('issues', [])))

    def sqlmap_fingerprint(self):
        target = self.renderer.input_prompt("타깃 URL 또는 --data 문자열 입력")
        self.renderer.print_loading("sqlmap fingerprint")
        out = self.sqlmap.fingerprint(target)
        if out.get('error'):
            self.renderer.print_error(out.get('error'))
        else:
            txt = out.get('stdout', '')[:4000]
            self.renderer.print_result_box("sqlmap Fingerprint", txt)
            self.report_gen.add_structured_finding('sqlmap', 'fingerprint', target, 'completed', metadata={'fingerprint': txt[:400]}, raw_output=txt)

    def sqlmap_dump_menu(self):
        target = self.renderer.input_prompt("타깃 URL 또는 --data 문자열 입력")
        db = self.renderer.input_prompt("덤프할 DB명 입력 (없으면 전체)")
        table = self.renderer.input_prompt("특정 테이블명 입력 (없으면 전체)")
        self.renderer.print_loading("sqlmap dump")
        out = self.sqlmap.dump(target, db if db else None, table if table else None)
        if out.get('error'):
            self.renderer.print_error(out.get('error'))
        else:
            txt = out.get('stdout', '')[:4000]
            self.renderer.print_result_box("sqlmap Dump", txt)
            self.report_gen.add_structured_finding('sqlmap', 'dump', target, 'completed', metadata={'db': db or '', 'table': table or ''}, raw_output=txt)

    def sqlmap_custom_menu(self):
        raw = self.renderer.input_prompt("sqlmap에 전달할 전체 인자 입력 (예: -u https://target.com -p id --batch)")
        args = raw.split()
        self.renderer.print_loading("sqlmap custom")
        out = self.sqlmap.custom(args)
        if out.get('error'):
            self.renderer.print_error(out.get('error'))
        else:
            txt = out.get('stdout', '')[:4000]
            self.renderer.print_result_box("sqlmap Custom Output", txt)
            self.report_gen.add_structured_finding('sqlmap', 'custom', ' '.join(args), 'completed', metadata={}, raw_output=txt)

    def sqlmap_set_path(self):
        p = self.renderer.input_prompt("sqlmap 경로 입력 (절대경로 또는 repo 내부 경로)")
        if not p:
            self.renderer.print_error("빈 경로입니다.")
            return
        if not os.path.exists(p):
            self.renderer.print_error("입력한 경로에 파일이 없습니다.")
            return
        # persist in config
        cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
        try:
            with open(cfg_path, 'r') as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
        if 'tools' not in cfg:
            cfg['tools'] = {}
        cfg['tools']['sqlmap_path'] = p
        with open(cfg_path, 'w') as f:
            json.dump(cfg, f, indent=2)
        self.sqlmap.sqlmap_path = p
        self.renderer.print_success(f"sqlmap 경로가 설정되었습니다: {p}")

    def sqlmap_show_path(self):
        p = getattr(self.sqlmap, 'sqlmap_path', None)
        if p:
            self.renderer.print_info(f"현재 sqlmap 경로: {p}")
        else:
            self.renderer.print_error("sqlmap 경로가 설정되어 있지 않음")

    def sqlmap_refresh(self):
        self.sqlmap.sqlmap_path = self.sqlmap._find_sqlmap()
        if self.sqlmap.is_available():
            self.renderer.print_success(f"sqlmap 감지됨: {self.sqlmap.sqlmap_path}")
        else:
            self.renderer.print_error("sqlmap 감지 실패")

    def sqlmap_batch_scan(self):
        raw = self.renderer.input_prompt("대상 목록 파일 경로 또는 쉼표 구분 다중 타깃 입력")
        targets = []
        if os.path.exists(raw):
            try:
                with open(raw, 'r') as f:
                    targets = [l.strip() for l in f if l.strip()]
            except Exception as e:
                self.renderer.print_error(str(e))
                return
        else:
            targets = [t.strip() for t in raw.split(',') if t.strip()]

        if not targets:
            self.renderer.print_error('타깃 없음')
            return

        timeout = 120
        for t in targets:
            self.renderer.print_loading(f"Batch quick scan: {t}")
            out = self.sqlmap.run_and_parse(['-u', t, '--batch', '--level=1', '--risk=1'], timeout=timeout)
            if out.get('error'):
                self.renderer.print_error(f"{t}: {out.get('error')}")
                continue
            raw = out.get('raw', {})
            parsed = out.get('parsed', {})
            self.renderer.print_result_box(f"{t} - results summary", '\n'.join(parsed.get('issues', [])[:6]) or 'No issues found')
            details = []
            details.append(f"issues={len(parsed.get('issues', []))}")
            details.append(f"databases={len(parsed.get('databases', []))}")
            self.report_gen.add_structured_finding('sqlmap', 'batch_quick', t, 'completed', metadata={'summary': ';'.join(details)}, raw_output=raw.get('stdout',''))
            self.stats.increment_stat('scans_performed')
            self.stats.increment_stat('findings', len(parsed.get('issues', [])))

    def sqlmap_batch_scan_parallel(self):
        raw = self.renderer.input_prompt("대상 목록 파일 경로 또는 쉼표 구분 다중 타깃 입력")
        targets = []
        if os.path.exists(raw):
            try:
                with open(raw, 'r') as f:
                    targets = [l.strip() for l in f if l.strip()]
            except Exception as e:
                self.renderer.print_error(str(e))
                return
        else:
            targets = [t.strip() for t in raw.split(',') if t.strip()]

        if not targets:
            self.renderer.print_error('타깃 없음')
            return

        threads_in = self.renderer.input_prompt("동시 실행할 스레드 수 입력 (기본 5)")
        try:
            threads = max(1, int(threads_in))
        except:
            threads = 5

        timeout = 120
        from concurrent.futures import ThreadPoolExecutor, as_completed

        self.renderer.print_loading("Starting parallel batch scans")
        entries = []
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(self.sqlmap.run_and_parse, ['-u', t, '--batch', '--level=1', '--risk=1'], timeout): t for t in targets}
            for fut in as_completed(futures):
                t = futures[fut]
                try:
                    out = fut.result()
                except Exception as e:
                    self.renderer.print_error(f"{t}: {e}")
                    continue
                if out.get('error'):
                    self.renderer.print_error(f"{t}: {out.get('error')}")
                    continue
                raw = out.get('raw', {})
                parsed = out.get('parsed', {})
                summary = ';'.join([f"issues={len(parsed.get('issues',[]))}", f"dbs={len(parsed.get('databases',[]))}"])
                self.report_gen.add_structured_finding('sqlmap', 'batch_quick_parallel', t, 'completed', metadata={'summary': summary, 'issues': parsed.get('issues',[])}, raw_output=raw.get('stdout',''))
                self.renderer.print_result_box(f"{t} - Parallel scan", '\n'.join(parsed.get('issues', [])[:6]) or 'No issues found')
                self.stats.increment_stat('scans_performed')
                self.stats.increment_stat('findings', len(parsed.get('issues', [])))
    
    def auth_menu(self):
        self.renderer.print_section("Authentication Testing")
        
        credentials = self.auth_module.generate_common_credentials()
        self.renderer.print_info("Common Credentials:")
        
        for username, password in credentials:
            self.renderer.print_option(0, f"{username}:{password}")
        
        password = self.renderer.input_prompt("비밀번호 강도 확인할 비밀번호 입력")
        strength = self.auth_module.check_password_strength(password)
        
        self.renderer.print_section("Password Strength Analysis")
        for check, result in strength['checks'].items():
            status = f"{Symbol.CHECK} Pass" if result else f"{Symbol.CROSS} Fail"
            print(f"  {check}: {status}")
        print(f"  {Color.CYAN}Strength Score: {strength['strength']}/5{Color.RESET}")
    
    def ssl_menu(self):
        self.renderer.print_section("SSL/TLS Testing")
        
        self.renderer.print_info("Weak Protocols:")
        for protocol in self.ssl_module.check_weak_protocols():
            self.renderer.print_option(0, protocol)
        
        self.renderer.print_info("Weak Ciphers:")
        for cipher in self.ssl_module.check_weak_ciphers():
            self.renderer.print_option(0, cipher)
    
    def headers_menu(self):
        self.renderer.print_section("Security Headers")
        
        recommended = self.headers_module.generate_recommended_headers()
        
        for header, value in recommended.items():
            print(f"{Color.CYAN}{header}:{Color.RESET} {value}")
    
    def encoding_menu(self):
        menu = self.menu_system.create_menu("Encoding/Decoding")
        
        encodings = ["Base64", "URL", "Hex", "HTML", "ROT13", "Caesar"]
        
        for enc in encodings:
            menu.add_option(
                enc,
                lambda e=enc: self.encoding_submenu(e),
                f"{enc} 인코딩/디코딩"
            )
        
        menu.add_option(
            "Hash Text",
            self.hash_menu,
            "텍스트 해싱"
        )
        
        self.menu_system.show_menu(menu)
    
    def encoding_submenu(self, encoding: str):
        menu = self.menu_system.create_menu(f"{encoding} Encoding/Decoding")
        
        menu.add_option(
            "Encode",
            lambda: self.encode_text(encoding),
            f"텍스트 {encoding} 인코딩"
        )
        
        menu.add_option(
            "Decode",
            lambda: self.decode_text(encoding),
            f"텍스트 {encoding} 디코딩"
        )
        
        self.menu_system.show_menu(menu)
    
    def encode_text(self, encoding: str):
        text = self.renderer.input_prompt(f"인코딩할 텍스트 입력")
        
        encode_func = {
            "Base64": self.encoding_module.base64_encode,
            "URL": self.encoding_module.url_encode,
            "Hex": self.encoding_module.hex_encode,
            "HTML": self.encoding_module.html_encode,
            "ROT13": self.encoding_module.rot13_encode,
            "Caesar": lambda x: self.encoding_module.caesar_encode(x, 3),
        }.get(encoding, str)
        
        result = encode_func(text)
        
        self.renderer.print_result_box(f"{encoding} Encoded", result)
        self.copy_to_clipboard(result)
        self.renderer.print_success("클립보드에 복사됨")
    
    def decode_text(self, encoding: str):
        text = self.renderer.input_prompt(f"디코딩할 텍스트 입력")
        
        decode_func = {
            "Base64": self.encoding_module.base64_decode,
            "URL": self.encoding_module.url_decode,
            "Hex": self.encoding_module.hex_decode,
            "HTML": self.encoding_module.html_decode,
            "ROT13": self.encoding_module.rot13_encode,
            "Caesar": lambda x: self.encoding_module.caesar_decode(x, 3),
        }.get(encoding, str)
        
        result = decode_func(text)
        
        self.renderer.print_result_box(f"{encoding} Decoded", result)
        self.copy_to_clipboard(result)
        self.renderer.print_success("클립보드에 복사됨")
    
    def hash_menu(self):
        text = self.renderer.input_prompt("해싱할 텍스트 입력")
        
        algorithms = ["md5", "sha1", "sha256", "sha512"]
        
        menu = self.menu_system.create_menu("Select Hash Algorithm")
        for algo in algorithms:
            menu.add_option(
                algo.upper(),
                lambda a=algo: self.hash_text(text, a),
                f"{algo.upper()} 해싱"
            )
        
        self.menu_system.show_menu(menu)
    
    def hash_text(self, text: str, algorithm: str):
        result = self.encoding_module.hash_text(text, algorithm)
        self.renderer.print_result_box(f"{algorithm.upper()} Hash", result)
        self.copy_to_clipboard(result)
        self.renderer.print_success("클립보드에 복사됨")
    
    def network_menu(self):
        menu = self.menu_system.create_menu("Network Tools")
        
        menu.add_option(
            "Port Scanner",
            self.port_scanner_menu,
            "포트 스캔"
        )
        
        menu.add_option(
            "DNS Enumeration",
            self.dns_enum_menu,
            "DNS 정보 수집"
        )
        
        menu.add_option(
            "Network Reconnaissance",
            self.network_recon_menu,
            "네트워크 정찰"
        )
        
        self.menu_system.show_menu(menu)
    
    def port_scanner_menu(self):
        host = self.renderer.input_prompt("스캔할 호스트 주소 입력")
        
        menu = self.menu_system.create_menu("Port Scanning")
        
        menu.add_option(
            "Scan Common Ports",
            lambda: self.scan_common_ports(host),
            "일반적인 포트 스캔"
        )
        
        menu.add_option(
            "Custom Port Range",
            lambda: self.scan_custom_ports(host),
            "사용자 정의 포트 스캔"
        )
        
        self.menu_system.show_menu(menu)
    
    def scan_common_ports(self, host: str):
        threads_input = self.renderer.input_prompt("스레드 수 입력 (기본 20)")
        try:
            threads = int(threads_input)
        except:
            threads = 20

        self.renderer.print_loading("Scanning")
        # use the detailed scanner to collect banners and service info
        ports_list = [21,22,23,25,53,80,110,143,443,445,3306,5432,5984,6379,8080,8443,9200,27017]
        results = self.port_scanner.scan_ports_detailed(host, ports_list, threads=threads)
        
        self.renderer.print_section(f"Port Scan Results for {host}")
        
        open_ports = [port for port, info in results.items() if info.get('open')]
        
        if open_ports:
            for port in sorted(open_ports):
                info = results.get(port, {})
                service = info.get('service') or self.port_scanner.get_service_name(port)
                banner = info.get('banner','')
                short_banner = (banner[:300] + '...') if banner and len(banner) > 300 else (banner or '')
                self.renderer.print_success(f"Port {port} - Open ({service})")
                if short_banner:
                    self.renderer.print_result_box(f"Banner (port {port})", short_banner)
                # structured report entry
                metadata = {'port': port, 'service': service}
                if banner:
                    metadata['banner_sample'] = banner[:1000]
                self.report_gen.add_structured_finding('port_scanner', 'open_port', host, 'open', metadata=metadata, raw_output=banner)
        else:
            self.renderer.print_warning("No open ports found")
        
        self.stats.increment_stat("scans_performed")
    
    def scan_custom_ports(self, host: str):
        ports_input = self.renderer.input_prompt("포트 범위 입력 (예: 1-100 또는 80,443,8080)")
        
        ports = []
        for part in ports_input.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        threads_input = self.renderer.input_prompt("스레드 수 입력 (기본 50)")
        try:
            threads = int(threads_input)
        except:
            threads = 50

        self.renderer.print_loading("Scanning")

        self.renderer.print_section(f"Port Scan Results for {host}")

        results = self.port_scanner.scan_ports_detailed(host, ports, threads=threads)
        for port in sorted(results.keys()):
            info = results.get(port, {})
            if info.get('open'):
                service = info.get('service') or self.port_scanner.get_service_name(port)
                banner = info.get('banner','')
                short_banner = (banner[:300] + '...') if banner and len(banner) > 300 else (banner or '')
                self.renderer.print_success(f"Port {port} - Open ({service})")
                if short_banner:
                    self.renderer.print_result_box(f"Banner (port {port})", short_banner)
                metadata = {'port': port, 'service': service}
                if banner:
                    metadata['banner_sample'] = banner[:1000]
                self.report_gen.add_structured_finding('port_scanner', 'open_port', host, 'open', metadata=metadata, raw_output=banner)
        
        self.stats.increment_stat("scans_performed")
    
    def dns_enum_menu(self):
        domain = self.renderer.input_prompt("도메인 입력")
        
        self.renderer.print_loading("Enumerating")
        
        self.renderer.print_section(f"DNS Information for {domain}")
        
        ips = self.dns_enum.resolve_domain(domain)
        if ips:
            for ip in ips:
                self.renderer.print_info(f"A Record: {ip}")
        
        self.renderer.print_info("Common Subdomains:")
        for subdomain in self.dns_enum.subdomain_wordlist()[:5]:
            full_domain = f"{subdomain}.{domain}"
            self.renderer.print_option(0, full_domain)
    
    def network_recon_menu(self):
        host = self.renderer.input_prompt("호스트 주소 입력")
        
        self.renderer.print_section(f"Network Reconnaissance for {host}")
        
        port = 80
        banner = self.network_recon.banner_grabbing(host, port)
        
        if banner:
            self.renderer.print_result_box("Banner Grabbing", banner)
        else:
            self.renderer.print_warning("No banner retrieved")
    
    def show_statistics(self):
        stats = self.stats.get_stats()
        
        self.renderer.print_section("Statistics")
        
        print(f"\n{Color.CYAN}{Color.BOLD}Session Statistics:{Color.RESET}")
        print(f"  {Symbol.STAR} Payloads Generated: {stats['payloads_generated']}")
        print(f"  {Symbol.STAR} Payloads Used: {stats['payloads_used']}")
        print(f"  {Symbol.STAR} Encodings Performed: {stats['encodings_performed']}")
        print(f"  {Symbol.STAR} Scans Performed: {stats['scans_performed']}")
        print(f"  {Symbol.STAR} Findings: {stats['findings']}\n")

    def show_findings(self):
        items = self.report_gen.results
        if not items:
            self.renderer.print_warning("현재 보고서에 저장된 발견사항이 없습니다.")
            return

        self.renderer.print_section("Findings")
        for idx, f in enumerate(items, 1):
            target = f.get('target') or f.get('payload') or ''
            meta = f.get('metadata')
            meta_summary = ''
            if meta:
                keys = list(meta.keys())[:3]
                meta_summary = ', '.join(f"{k}={meta.get(k)}" for k in keys)
            print(f"[{idx}] {f.get('module')} - {f.get('type')} - {target} - {f.get('status')} {meta_summary}")

        choice = self.renderer.input_prompt("자세히 볼 항목 번호 입력 (뒤로: b)")
        if choice.lower() == 'b':
            return
        try:
            i = int(choice) - 1
            if i < 0 or i >= len(items):
                self.renderer.print_error("잘못된 선택")
                return
            entry = items[i]
            self.renderer.print_section(f"Finding Detail [{i+1}]")
            print(f"Module: {entry.get('module')}")
            print(f"Type: {entry.get('type')}")
            if entry.get('target'):
                print(f"Target: {entry.get('target')}")
            if entry.get('payload'):
                print(f"Payload: {entry.get('payload')}")
            if entry.get('metadata'):
                print("Metadata:")
                for k, v in entry.get('metadata', {}).items():
                    print(f"  - {k}: {v}")
            if entry.get('raw_output'):
                print('\n' + '='*60)
                print(entry.get('raw_output')[:3000])
                print('\n' + '='*60)
                save = self.renderer.input_choice("이 원시출력(raw output)을 파일로 저장하시겠습니까? (Y/N)")
                if save.lower() == 'y':
                    fname = self.renderer.input_prompt("저장할 파일명 입력 (확장자 포함)")
                    try:
                        with open(fname, 'w') as f:
                            f.write(entry.get('raw_output'))
                        self.renderer.print_success(f"저장됨: {fname}")
                    except Exception as e:
                        self.renderer.print_error(str(e))
        except ValueError:
            self.renderer.print_error("잘못된 입력")
    
    def show_help(self):
        self.help_system.show_main_help()
    
    def copy_to_clipboard(self, text: str):
        try:
            import subprocess
            process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
            process.communicate(text.encode('utf-8'))
        except:
            pass


def main():
    app = PurpleHatApplication()
    app.run()


if __name__ == "__main__":
    main()
