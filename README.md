# 🔐 IronKey Py - Gerenciador de Senhas Seguro

Um gerenciador de senhas robustas, com versão desktop moderno e seguro com interface gráfica, desenvolvido em Python.
Possui persistência e criptografia

<div align="center">

![Python](https://img.shields.io/badge/python-3.13-blue.svg)
![Customtkinter](https://img.shields.io/badge/customtkinter-5.2.2-blue.svg)
![Cryptography](https://img.shields.io/badge/cryptography-41.0.7-blue.svg)
![Status](https://img.shields.io/badge/status-completed-green)
[![Executável](https://img.shields.io/badge/baixar-execut%C3%A1vel-orange)](https://www.mediafire.com/file/tdn3vdhn76hwvh6/IronKey_Py.rar/file)

</div>

<div align="center">

  <img width="755px" src= https://i.ibb.co/Jwzw9ywr/main.png/>
  <img width="755px" src= https://i.ibb.co/svJ9H5YF/pass.png/>

 </div>

---

## ✨ Características

- Chave derivada da senha mestre com **PBKDF2** (100,000 iterações)

- 🎨 **Interface Moderna** - GUI intuitiva com CustomTkinter e tema dark
  - Salt único armazenado em `config.json`

- 🔒 **Criptografia AES-128** - Todas as senhas protegidas com Fernet
  - Impossível ler senhas sem a senha mestre correta

- 🔑 **Senha Mestre** - Acesso protegido com derivação PBKDF2 (100k iterações)
  - **Primeira execução:** Configure sua senha mestre (mínimo 6 caracteres)

- 🎲 **Gerador Seguro** - Senhas aleatórias criptograficamente seguras
  - Usa `secrets`

- 🔍 **Verificação HIBP** - Detecta senhas comprometidas via Have I Been Pwned 

- ⏱️ **Auto-Clear Clipboard** - Limpa senhas copiadas após 30 segundos- 

- 🔐 **Auto-Lock** - Bloqueia automaticamente após 5 minutos de inatividade
  - Senha incorreta = sem acesso às senhas
  - **Execuções seguintes:** Digite a senha mestre para desbloquear

- 💾 **Backup Criptografado** - Exporta/importa banco de dados com segurança
  - A senha mestre NÃO é armazenada, apenas um hash para verificação

---

## 🚀 Instalação

```bash
# Clone o repositório

git clone https://github.com/wilsondesouza/IronKeyPy.git
cd IronKeyPy
```

```bash
# Crie e ative o ambiente virtual

python -m venv venv
venv/scripts/activate
```

```bash
# Instale as dependências

pip install -r requirements.txt
```

---

## Criação do Executável
**Preparativos**
 - Tenha certeza de que as imagens (.ico e .png) estão com os caminhos absolutos no código principal `main.py`

1. Instale o pyinstaller
```bash
pip install pyinstaller
```

2. Copie o comando abaixo, alterando apenas o nome da aplicação e da imagem do ícone
```bash
pyinstaller --noconfirm --onefile --name "Sua aplicação" --windowed --add-data ".venv/Lib/site-packages/customtkinter;customtkinter/" --icon="assets/images/seuicone.ico" "main.py"
```

3. Confira o resultado
Será criado um arquivo `.spec` e as pastas `build` e `dist`. Seu aplicativo standalone e portable estará na pasta `dist`.

---

## 📝 Estrutura do Projeto

```bash
IronLeyPy/
├── main.py                    # Interface gráfica principal
├── database/ 
│   └── database.py            # Gerenciamento SQLite criptografado
├── services/ 
│   ├── password_generator.py  # Gerador de senhas seguro
│   └── crypto_manager.py      # Sistema de criptografia
├── api/
│   └── pwned_checker.py       # Verificação Have I Been Pwned
├── requirements.txt           # Dependências
└── README.md                  # Documentação
```

---

## 📁 Arquivos Importantes

- `ironkeypy.db` - Banco de dados criptografado (senhas)
- `config.json` - Configuração (salt + verificação de senha)
- `ironkeypy.db.old` - Backup automático (criado ao importar)

---

## ⚠️ IMPORTANTE

1. **NÃO PERCA SUA SENHA MESTRE** - Sem ela, suas senhas são irrecuperáveis

2. **Faça backups regulares** - Use a função de exportar

3. **Guarde backups em local seguro** - Eles estão criptografados mas mantenha seguros

4. **Não compartilhe o arquivo config.json** - Contém informações do sistema de criptografia

5. **Verifique senhas periodicamente** - Use a funcionalidade de verificação HIBP

---

## 🔐 Segurança Técnica

- **Criptografia:** AES-128 via Fernet (cryptography library)
- **KDF:** PBKDF2-HMAC-SHA256 com 100,000 iterações
- **Aleatoriedade:** módulo `secrets` (criptograficamente seguro)
- **Salt:** 16 bytes aleatórios únicos por instalação
- **Auto-lock:** 300 segundos (5 minutos) de timeout
- **Clipboard:** 30 segundos até limpeza automática
- **HIBP API:** `k-anonymity` com hash SHA-1 parcial (5 caracteres)
- **Privacidade:** Sua senha completa nunca sai do seu computador
  - O único uso do `requests` é para consultar a API do `Have I Been Pwned`

---

## 📦 Dependências

```bash
customtkinter==5.2.2
pyperclip==1.8.2
cryptography==41.0.7
requests==2.31.0
```

---

## 🌐 Sobre o Have I Been Pwned

A verificação de senhas usa a API do [Have I Been Pwned](https://haveibeenpwned.com/), um serviço criado por Troy Hunt que:
- Mantém banco de dados com **+12 bilhões** de senhas comprometidas
- Dados coletados de vazamentos públicos e breaches confirmados
- API gratuita e sem necessidade de registro
- **100% privada:** usa `k-anonymity` para nunca expor sua senha

### Como funciona a verificação:
1. Sua senha é convertida em hash SHA-1 localmente
2. Apenas os **primeiros 5 caracteres** do hash são enviados
3. API retorna **todos** os hashes que começam com esses 5 caracteres
4. Verificação local busca o hash completo nos resultados
5. Sua senha real **NUNCA** sai do seu computador