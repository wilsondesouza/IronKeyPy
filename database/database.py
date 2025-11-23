import sqlite3
from datetime import datetime
from typing import List, Tuple, Optional

# Classe para gerenciar o banco de dados de senhas
class PasswordDatabase:
    def __init__(self, db_name: str = "ironkeypy.db", crypto_manager=None):
        self.db_name = db_name
        self.crypto_manager = crypto_manager
        self.create_table()
    
    def set_crypto_manager(self, crypto_manager):
        self.crypto_manager = crypto_manager
    
    def create_table(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()
    
    # Adiciona uma nova senha ao banco de dados (criptografada)
    def add_password(self, site: str, username: str, password: str) -> bool:
        
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Criptografar a senha se o crypto_manager estiver disponível
            encrypted_password = password
            if self.crypto_manager:
                encrypted_password = self.crypto_manager.encrypt(password)
            
            cursor.execute('''
                INSERT INTO passwords (site, username, password, created_at)
                VALUES (?, ?, ?, ?)
            ''', (site, username, encrypted_password, created_at))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Erro ao adicionar senha: {e}")
            return False
    
    def get_all_passwords(self) -> List[Tuple]:
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('SELECT id, site, username, password, created_at FROM passwords ORDER BY created_at DESC')
        passwords = cursor.fetchall()
        conn.close()
        
        # Descriptografar senhas
        decrypted_passwords = []
        for pwd_id, site, username, encrypted_password, created_at in passwords:
            try:
                if self.crypto_manager:
                    password = self.crypto_manager.decrypt(encrypted_password)
                else:
                    password = encrypted_password
                decrypted_passwords.append((pwd_id, site, username, password, created_at))
            except Exception as e:
                print(f"Erro ao descriptografar senha {pwd_id}: {e}")
                # Se for erro de padding/base64, provavelmente é senha antiga em texto puro
                error_msg = str(e)
                if "Incorrect padding" in error_msg or "base64" in error_msg or "Invalid" in error_msg:
                    decrypted_passwords.append((pwd_id, site, username, "[Senha antiga não criptografada]", created_at))
                else:
                    decrypted_passwords.append((pwd_id, site, username, "[Erro ao descriptografar]", created_at))
        
        return decrypted_passwords
    
    def delete_password(self, password_id: int) -> bool:
        
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Erro ao deletar senha: {e}")
            return False
    
    def search_passwords(self, search_term: str) -> List[Tuple]:
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, site, username, password, created_at 
            FROM passwords 
            WHERE site LIKE ? OR username LIKE ?
            ORDER BY created_at DESC
        ''', (f'%{search_term}%', f'%{search_term}%'))
        passwords = cursor.fetchall()
        conn.close()
        
        # Descriptografar senhas
        decrypted_passwords = []
        for pwd_id, site, username, encrypted_password, created_at in passwords:
            try:
                if self.crypto_manager:
                    password = self.crypto_manager.decrypt(encrypted_password)
                else:
                    password = encrypted_password
                decrypted_passwords.append((pwd_id, site, username, password, created_at))
            except Exception as e:
                print(f"Erro ao descriptografar senha {pwd_id}: {e}")
                decrypted_passwords.append((pwd_id, site, username, "[Erro ao descriptografar]", created_at))
        
        return decrypted_passwords