import secrets
import string

# Classe para geração e avaliação de senhas
class PasswordGenerator:
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Gera uma senha aleatória criptograficamente segura com base nos critérios fornecidos
    def generate_password(self, length: int = 12, use_lowercase: bool = True, 
                         use_uppercase: bool = True, use_digits: bool = True, 
                         use_symbols: bool = True) -> str:
        
        if length < 4:
            length = 4
        
        # Construir conjunto de caracteres disponíveis
        available_chars = ""
        required_chars = []
        
        if use_lowercase:
            available_chars += self.lowercase
            required_chars.append(secrets.choice(self.lowercase))
        
        if use_uppercase:
            available_chars += self.uppercase
            required_chars.append(secrets.choice(self.uppercase))
        
        if use_digits:
            available_chars += self.digits
            required_chars.append(secrets.choice(self.digits))
        
        if use_symbols:
            available_chars += self.symbols
            required_chars.append(secrets.choice(self.symbols))
        
        # Se nenhum critério foi selecionado, usar todos
        if not available_chars:
            available_chars = self.lowercase + self.uppercase + self.digits + self.symbols
            required_chars = [
                secrets.choice(self.lowercase),
                secrets.choice(self.uppercase),
                secrets.choice(self.digits),
                secrets.choice(self.symbols)
            ]
        
        # Preencher o resto da senha
        remaining_length = length - len(required_chars)
        if remaining_length > 0:
            password_chars = required_chars + [secrets.choice(available_chars) for _ in range(remaining_length)]
        else:
            password_chars = required_chars[:length]
        
        # Embaralhar os caracteres usando secrets
        password_chars_copy = password_chars.copy()
        shuffled = []
        while password_chars_copy:
            index = secrets.randbelow(len(password_chars_copy))
            shuffled.append(password_chars_copy.pop(index))
        
        return ''.join(shuffled)
    
    def calculate_strength(self, password: str) -> tuple[str, int]:

        score = 0
        
        # Comprimento
        if len(password) >= 12:
            score += 25
        elif len(password) >= 8:
            score += 15
        elif len(password) >= 6:
            score += 10
        
        # Variedade de caracteres
        if any(c in self.lowercase for c in password):
            score += 20
        if any(c in self.uppercase for c in password):
            score += 20
        if any(c in self.digits for c in password):
            score += 20
        if any(c in self.symbols for c in password):
            score += 15
        
        # Descrição
        if score >= 80:
            description = "Muito Forte"
        elif score >= 60:
            description = "Forte"
        elif score >= 40:
            description = "Média"
        elif score >= 20:
            description = "Fraca"
        else:
            description = "Muito Fraca"
        
        return description, score