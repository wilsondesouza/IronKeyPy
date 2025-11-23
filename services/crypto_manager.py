from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import json

# Gerenciamento de criptografia
class CryptoManager:
    
    def __init__(self, config_file: str = "config.json"):
        
        self.config_file = config_file
        self.fernet = None
        self.salt = None
        self.load_or_create_config()
    
    
    def load_or_create_config(self):

        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                self.salt = base64.b64decode(config['salt'])
        else:
            # Gerar novo salt
            self.salt = os.urandom(16)
            config = {
                'salt': base64.b64encode(self.salt).decode('utf-8'),
                'initialized': False
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
    
    
    def derive_key(self, master_password: str) -> bytes:

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key
    
    
    def initialize(self, master_password: str) -> bool:

        try:
            key = self.derive_key(master_password)
            self.fernet = Fernet(key)
            return True
        except Exception as e:
            print(f"Erro ao inicializar criptografia: {e}")
            return False
    
    
    def encrypt(self, data: str) -> str:

        if not self.fernet:
            raise Exception("CryptoManager não inicializado!")
        
        encrypted = self.fernet.encrypt(data.encode())
        return base64.b64encode(encrypted).decode('utf-8')
    
    
    def decrypt(self, encrypted_data: str) -> str:

        if not self.fernet:
            raise Exception("CryptoManager não inicializado!")
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
        except Exception as e:
            raise Exception(f"Erro ao descriptografar: {e}")
    
    
    def verify_master_password(self, master_password: str) -> bool:
        
        try:
            key = self.derive_key(master_password)
            test_fernet = Fernet(key)
            
            # Tentar descriptografar um teste
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            if 'test_data' in config:
                try:
                    test_fernet.decrypt(base64.b64decode(config['test_data']))
                    return True
                except:
                    return False
            return True  # Primeira vez
        except:
            return False
    
    
    def set_master_password(self, master_password: str):
        
        key = self.derive_key(master_password)
        self.fernet = Fernet(key)
        
        # Criar dado de teste para verificar senha futura
        test_data = self.fernet.encrypt(b"test")
        
        with open(self.config_file, 'r') as f:
            config = json.load(f)
        
        config['test_data'] = base64.b64encode(test_data).decode('utf-8')
        config['initialized'] = True
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f)
    
    
    # Verifica se a senha mestre já foi configurada
    def is_initialized(self) -> bool:
        
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                return config.get('initialized', False)
        return False
