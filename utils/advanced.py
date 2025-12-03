import json
from typing import Dict, Any, List
from datetime import datetime
import os


class ReportGenerator:
    def __init__(self):
        self.results = []
        self.start_time = datetime.now()
    
    def add_finding(self, module: str, finding_type: str, payload: str, status: str, details: str = ""):
        self.results.append({
            "timestamp": datetime.now().isoformat(),
            "module": module,
            "type": finding_type,
            "payload": payload,
            "status": status,
            "details": details
        })

    def add_structured_finding(self, module: str, finding_type: str, target: str, status: str, metadata: Dict = None, raw_output: str = None):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "module": module,
            "type": finding_type,
            "target": target,
            "status": status,
            "metadata": metadata or {},
        }
        if raw_output is not None:
            entry["raw_output"] = raw_output
        self.results.append(entry)
    
    def generate_json_report(self, filepath: str):
        report = {
            "framework": "PURPLE HAT",
            "scan_start": self.start_time.isoformat(),
            "scan_end": datetime.now().isoformat(),
            "total_findings": len(self.results),
            "findings": self.results
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
    
    def generate_text_report(self, filepath: str):
        with open(filepath, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("PURPLE HAT - Security Testing Report\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Scan Start: {self.start_time.isoformat()}\n")
            f.write(f"Scan End: {datetime.now().isoformat()}\n")
            f.write(f"Total Findings: {len(self.results)}\n\n")
            
            for idx, finding in enumerate(self.results, 1):
                f.write(f"[{idx}] {finding.get('module','unknown')} - {finding.get('type','') }\n")
                f.write(f"    Status: {finding.get('status')}\n")
                if 'target' in finding:
                    f.write(f"    Target: {finding.get('target')}\n")
                if 'payload' in finding:
                    f.write(f"    Payload: {finding.get('payload')}\n")
                if finding.get('metadata'):
                    f.write(f"    Metadata:\n")
                    for k, v in finding.get('metadata', {}).items():
                        f.write(f"      - {k}: {v}\n")
                if finding.get('raw_output'):
                    f.write(f"    Raw Output (truncated):\n")
                    f.write(f"{finding.get('raw_output')[:1000]}\n")
                else:
                    f.write(f"    Details: {finding.get('details','')}\n\n")


class PayloadValidator:
    @staticmethod
    def validate_sql_payload(payload: str) -> bool:
        keywords = ['union', 'select', 'insert', 'update', 'delete', 'drop']
        return any(kw in payload.lower() for kw in keywords)
    
    @staticmethod
    def validate_xss_payload(payload: str) -> bool:
        xss_markers = ['<script', 'onerror=', 'onload=', 'javascript:']
        return any(marker in payload.lower() for marker in xss_markers)
    
    @staticmethod
    def validate_command_payload(payload: str) -> bool:
        dangerous_chars = [';', '|', '&', '`', '$']
        return any(char in payload for char in dangerous_chars)


class SessionManager:
    def __init__(self, session_dir: str = ".purple_hat_sessions"):
        self.session_dir = session_dir
        if not os.path.exists(session_dir):
            os.makedirs(session_dir)
    
    def save_session(self, session_name: str, data: Dict[str, Any]):
        filepath = os.path.join(self.session_dir, f"{session_name}.json")
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_session(self, session_name: str) -> Dict[str, Any]:
        filepath = os.path.join(self.session_dir, f"{session_name}.json")
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
        return {}
    
    def list_sessions(self) -> List[str]:
        return [f[:-5] for f in os.listdir(self.session_dir) if f.endswith('.json')]


class StatisticsTracker:
    def __init__(self):
        self.stats = {
            "payloads_generated": 0,
            "payloads_used": 0,
            "encodings_performed": 0,
            "scans_performed": 0,
            "findings": 0,
        }
    
    def increment_stat(self, stat_name: str, amount: int = 1):
        if stat_name in self.stats:
            self.stats[stat_name] += amount
    
    def get_stats(self) -> Dict[str, int]:
        return self.stats.copy()
    
    def reset_stats(self):
        for key in self.stats:
            self.stats[key] = 0
