import base64
import hashlib
import urllib.parse
from typing import Dict


class EncodingModule:
    def __init__(self):
        self.name = "Encoding & Decoding"
        self.description = "다양한 인코딩/디코딩 도구"
    
    def base64_encode(self, text: str) -> str:
        return base64.b64encode(text.encode()).decode()
    
    def base64_decode(self, text: str) -> str:
        try:
            return base64.b64decode(text).decode()
        except:
            return "[!] Decoding failed"
    
    def url_encode(self, text: str) -> str:
        return urllib.parse.quote(text)
    
    def url_decode(self, text: str) -> str:
        return urllib.parse.unquote(text)
    
    def hex_encode(self, text: str) -> str:
        return text.encode().hex()
    
    def hex_decode(self, text: str) -> str:
        try:
            return bytes.fromhex(text).decode()
        except:
            return "[!] Decoding failed"
    
    def html_encode(self, text: str) -> str:
        import html
        return html.escape(text)
    
    def html_decode(self, text: str) -> str:
        import html
        return html.unescape(text)
    
    def morse_encode(self, text: str) -> str:
        morse_code_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--',
            '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.'
        }
        return ' '.join(morse_code_dict.get(c.upper(), '') for c in text if c.upper() in morse_code_dict)
    
    def rot13_encode(self, text: str) -> str:
        return text.translate(str.maketrans(
            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM'
        ))
    
    def caesar_encode(self, text: str, shift: int = 3) -> str:
        result = []
        for char in text:
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - start + shift) % 26 + start))
            else:
                result.append(char)
        return ''.join(result)
    
    def caesar_decode(self, text: str, shift: int = 3) -> str:
        return self.caesar_encode(text, -shift)
    
    def get_all_encodings(self, text: str) -> Dict[str, str]:
        return {
            "Base64": self.base64_encode(text),
            "URL": self.url_encode(text),
            "Hex": self.hex_encode(text),
            "HTML": self.html_encode(text),
            "ROT13": self.rot13_encode(text),
            "Caesar(+3)": self.caesar_encode(text, 3),
        }
    
    def hash_text(self, text: str, algorithm: str = "md5") -> str:
        hash_functions = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
        }
        func = hash_functions.get(algorithm, hashlib.md5)
        return func(text.encode()).hexdigest()
