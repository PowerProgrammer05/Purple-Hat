from typing import List, Dict, Any


class Logger:
    def __init__(self, filename: str = "purple_hat.log"):
        self.filename = filename
        self.logs = []
    
    def log(self, level: str, message: str):
        self.logs.append(f"[{level}] {message}")
    
    def save_to_file(self):
        with open(self.filename, 'w') as f:
            f.write('\n'.join(self.logs))


class ConfigManager:
    def __init__(self):
        self.config = {
            "timeout": 5,
            "retries": 3,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "proxy_enabled": False,
            "proxy_url": "http://127.0.0.1:8080",
        }
    
    def get(self, key: str, default=None):
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        self.config[key] = value
    
    def load_from_file(self, filepath: str):
        import json
        try:
            with open(filepath, 'r') as f:
                self.config.update(json.load(f))
        except:
            pass
    
    def save_to_file(self, filepath: str):
        import json
        with open(filepath, 'w') as f:
            json.dump(self.config, f, indent=2)


class PayloadManager:
    def __init__(self):
        self.payloads = {}
    
    def add_payload(self, category: str, name: str, payload: str):
        if category not in self.payloads:
            self.payloads[category] = {}
        self.payloads[category][name] = payload
    
    def get_payloads(self, category: str) -> Dict:
        return self.payloads.get(category, {})
    
    def list_categories(self) -> List[str]:
        return list(self.payloads.keys())
    
    def export_payloads(self, filepath: str):
        import json
        with open(filepath, 'w') as f:
            json.dump(self.payloads, f, indent=2)
