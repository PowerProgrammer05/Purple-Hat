import os
import json
import subprocess
from typing import List, Dict, Optional

from pathlib import Path

class SQLMapWrapper:
    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        self.base_dir = base_dir
        self.sqlmap_path = self._find_sqlmap()

    def _find_sqlmap(self) -> Optional[str]:
        env_path = os.environ.get('PURPLEHAT_SQLMAP_PATH')
        if env_path and os.path.exists(env_path):
            return env_path

        try:
            cfg_path = Path(self.base_dir) / 'config.json'
            if cfg_path.exists():
                cfg = json.loads(cfg_path.read_text())
                cfg_path_val = cfg.get('tools', {}).get('sqlmap_path')
                if cfg_path_val and Path(cfg_path_val).exists():
                    return str(Path(cfg_path_val).expanduser())
        except Exception:
            pass

        candidates = [
            os.path.join(self.base_dir, 'sqlmap-master copy', 'sqlmap.py'),
            os.path.join(self.base_dir, 'sqlmap-master', 'sqlmap.py'),
            os.path.join(self.base_dir, 'sqlmap', 'sqlmap.py'),
        ]
        for p in candidates:
            if os.path.exists(p):
                return p

        return None

    def is_available(self) -> bool:
        return self.sqlmap_path is not None

    def run(self, args: List[str], timeout: int = 120) -> Dict[str, str]:
        if not self.is_available():
            return {'error': 'sqlmap not found'}
        python_exec = os.environ.get('PYTHON', 'python3')
        cmd = [python_exec, self.sqlmap_path] + args
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = proc.communicate(timeout=timeout)
            return {
                'returncode': str(proc.returncode),
                'stdout': out.decode('utf-8', errors='ignore'),
                'stderr': err.decode('utf-8', errors='ignore')
            }
        except subprocess.TimeoutExpired:
            proc.kill()
            return {'error': 'timeout', 'stdout': '', 'stderr': ''}
        except Exception as e:
            return {'error': str(e)}

    def parse_findings(self, raw_output: str) -> Dict[str, List[str]]:
        findings = {'issues': [], 'databases': [], 'other': []}
        for line in raw_output.splitlines():
            l = line.strip()
            if not l:
                continue
            lowered = l.lower()
            if 'is vulnerable' in lowered or 'heuristic' in lowered or 'sql injection' in lowered:
                findings['issues'].append(l)
            elif 'current db' in lowered or 'current database' in lowered or 'database management system' in lowered:
                findings['databases'].append(l)
            else:
                if len(l) < 300:
                    findings['other'].append(l)
        return findings

    def quick_scan(self, target: str) -> Dict[str, str]:
        args = ['-u', target, '--batch', '--level=1', '--risk=1']
        return self.run(args)

    def fingerprint(self, target: str) -> Dict[str, str]:
        args = ['-u', target, '--batch', '--fingerprint']
        return self.run(args)

    def dump(self, target: str, db: Optional[str] = None, table: Optional[str] = None) -> Dict[str, str]:
        args = ['-u', target, '--batch', '--dump']
        if db:
            args += ['-D', db]
        if table:
            args += ['-T', table]
        return self.run(args)

    def custom(self, raw_args: List[str]) -> Dict[str, str]:
        return self.run(raw_args)

    def run_and_parse(self, args: List[str], timeout: int = 120) -> Dict[str, object]:
        raw = self.run(args, timeout=timeout)
        if 'error' in raw:
            return {'error': raw.get('error'), 'stdout': raw.get('stdout', ''), 'stderr': raw.get('stderr', '')}
        txt = raw.get('stdout', '')
        parsed = self.parse_findings(txt)
        return {'raw': raw, 'parsed': parsed}
