import hashlib
import requests
from typing import Tuple

# Verifica se senhas ou emails foram comprometidos usando a API Have I Been Pwned
class PwnedChecker:
    
    def __init__(self):
        self.password_api_url = "https://api.pwnedpasswords.com/range/"
        self.breach_api_url = "https://haveibeenpwned.com/api/v3/breachedaccount/"
        
    def check_password(self, password: str) -> Tuple[bool, int]:

        try:
            # Gerar hash SHA-1 da senha
            sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            
            # Usar k-anonymity: enviar apenas os primeiros 5 caracteres
            prefix = sha1_password[:5]
            suffix = sha1_password[5:]
            
            # Fazer requisição à API
            response = requests.get(
                f"{self.password_api_url}{prefix}",
                headers={'User-Agent': 'IronKeyPy-PasswordManager'},
                timeout=5
            )
            
            if response.status_code != 200:
                raise Exception(f"Erro na API: {response.status_code}")
            
            # Procurar o sufixo nos resultados
            hashes = response.text.splitlines()
            for line in hashes:
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    return True, int(count)
            
            # Senha não encontrada = segura
            return False, 0
            
        except requests.exceptions.Timeout:
            raise Exception("Timeout ao conectar com a API. Verifique sua conexão.")
        except requests.exceptions.ConnectionError:
            raise Exception("Erro de conexão. Verifique sua internet.")
        except Exception as e:
            raise Exception(f"Erro ao verificar senha: {str(e)}")
    
    
    def check_email(self, email: str, api_key: str = None) -> Tuple[bool, list]:
        
        if not api_key:
            return False, []
        
        try:
            headers = {
                'hibp-api-key': api_key,
                'User-Agent': 'IronKeyPy-PasswordManager'
            }
            
            response = requests.get(
                f"{self.breach_api_url}{email}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                breaches = response.json()
                breach_names = [breach['Name'] for breach in breaches]
                return True, breach_names
            elif response.status_code == 404:
                # Email não encontrado = seguro
                return False, []
            else:
                raise Exception(f"Erro na API: {response.status_code}")
                
        except Exception as e:
            raise Exception(f"Erro ao verificar email: {str(e)}")
    
    
    def get_password_strength_advice(self, is_pwned: bool, count: int) -> str:

        if not is_pwned:
            return "✅ Senha segura! Não encontrada em vazamentos conhecidos."
        elif count < 10:
            return f"⚠️ ALERTA: Esta senha apareceu {count}x em vazamentos. Considere mudá-la."
        elif count < 100:
            return f"🚨 PERIGO: Esta senha apareceu {count}x em vazamentos! Mude IMEDIATAMENTE."
        else:
            return f"🔴 CRÍTICO: Esta senha apareceu {count:,}x em vazamentos! NUNCA use esta senha!"
    
    
    def format_breach_info(self, breaches: list) -> str:

        if not breaches:
            return "✅ Email seguro! Não encontrado em vazamentos conhecidos."
        
        breach_list = "\n• ".join(breaches[:5])  # Mostrar no máximo 5
        total = len(breaches)
        
        if total <= 5:
            return f"🚨 ALERTA: Email encontrado em {total} vazamento(s):\n• {breach_list}"
        else:
            return f"🚨 ALERTA: Email encontrado em {total} vazamentos! Mostrando os 5 primeiros:\n• {breach_list}\n... e mais {total - 5}"
