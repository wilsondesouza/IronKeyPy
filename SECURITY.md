# Modelo de Segurança — IronKey Py 2.0

Este documento descreve **o que o IronKey Py protege, como protege e o que ele
explicitamente não protege**. Um gerenciador de senhas que não é honesto sobre
seus limites induz o usuário a um risco maior do que não usar nenhum.

---

## 1. Arquitetura criptográfica

```
                       senha mestre (nunca armazenada)
                                  │
                     Argon2id (t=4, m=128 MiB, p=4)
                                  ▼
                              KEK (32 B)
                                  │
                    AES-256-GCM (desembrulha)          AAD = cabeçalho do cofre
                                  ▼
                              DEK (32 B, aleatória)
                                  │
        ┌─────────────────────────┼──────────────────────────┐
        ▼                         ▼                          ▼
  registros do cofre       histórico de senhas        verificador de senha
  AES-256-GCM              AES-256-GCM                AES-256-GCM
  AAD = uid do registro    AAD = uid do registro
```

| Componente | Escolha | Por quê |
|---|---|---|
| Derivação de chave | **Argon2id** `t=4, m=128 MiB, p=4` | Resistente a GPU/ASIC por exigir memória. Fallback: PBKDF2-HMAC-SHA256 com 600.000 iterações (mínimo OWASP 2023). |
| Cifra | **AES-256-GCM** | AEAD: confidencialidade **e** autenticidade em uma operação. Detecta adulteração. |
| Nonce | 96 bits aleatórios por operação | Recomendação NIST SP 800-38D para GCM. |
| Chaves | Envelope **KEK/DEK** | Trocar a senha mestre reembrulha 32 bytes em vez de reescrever o cofre inteiro. |
| Salt | 16 bytes por cofre, `os.urandom` | Impede tabelas pré-computadas compartilhadas entre instalações. |
| Aleatoriedade | `secrets` / `os.urandom` | CSPRNG do sistema operacional. |
| Verificação de senha | Decifragem autenticada de um bloco-sentinela | **Falha fechada**: sem material válido, o acesso é negado. |

### Dados associados (AAD)

* O **cabeçalho do cofre** (versão, `vault_id`, parâmetros de KDF) é AAD da DEK
  embrulhada. Trocar o salt ou baixar o custo do Argon2id invalida a tag GCM.
* O **uid do registro** é AAD de cada registro. Um atacante com escrita no
  arquivo não consegue mover o ciphertext da senha do serviço A para o
  registro do serviço B (*cut-and-paste*).

---

## 2. O que fica cifrado

| Dado | v1 (versão anterior) | v2 (atual) |
|---|---|---|
| Senha | cifrada (Fernet / AES-128-CBC) | **AES-256-GCM** |
| Nome do site/serviço | ❌ **texto puro** | **cifrado** |
| Nome de usuário / e-mail | ❌ **texto puro** | **cifrado** |
| URL, notas, categoria | não existiam | **cifrados** |
| Segredo TOTP | não existia | **cifrado** |
| Histórico de senhas | não existia | **cifrado** |
| Datas de criação/alteração | texto puro | texto puro (necessárias para ordenar) |

---

## 3. Proteções operacionais

| Proteção | Comportamento |
|---|---|
| Auto-bloqueio | Configurável (padrão 5 min de inatividade), com aviso 30 s antes. Ao bloquear, a DEK é zerada na memória. |
| Limpeza da área de transferência | Configurável (padrão 30 s), com contagem regressiva visível. **Só limpa se o conteúdo ainda for o segredo copiado.** |
| Limite de tentativas | Backoff exponencial (15 s → 30 s → 1 min → … → 15 min), persistido entre execuções. |
| Reexibição de senha | O botão 👁 volta a ocultar sozinho após 20 s. |
| Escrita atômica | Cabeçalho e preferências gravados via arquivo temporário + `os.replace`. |
| Permissões | Pasta `0700`, arquivos `0600` em sistemas POSIX. |
| Zeragem de memória | Chaves vivem em `bytearray` e são sobrescritas ao bloquear (mitigação parcial — ver §5). |
| Verificação de vazamento | k-anonymity + cabeçalho `Add-Padding`; só 5 caracteres do SHA-1 saem da máquina. |
| Exportação em texto puro | Exige digitar a palavra `EXPORTAR`; o arquivo sugerido já se chama `...-INSEGURO.csv`. |

---

## 4. Backups

O formato **`.ikbak`** é autocontido: carrega o próprio salt, os parâmetros de
KDF e os dados cifrados com AES-256-GCM sob uma senha escolhida na exportação.
Pode ser restaurado em qualquer máquina, sem depender do `config.json` de
origem — ao contrário da v1, cujo "backup" era uma cópia do `.db` **impossível
de abrir** sem o `config.json` que ficava para trás.

A importação **valida o arquivo inteiro antes de tocar no cofre** e faz *merge*
sem apagar nada. A v1 sobrescrevia o banco primeiro e só depois descobria que o
arquivo era inválido.

---

## 5. Fora do escopo (limites honestos)

O IronKey Py protege **dados em repouso** em uma máquina que você controla.
Ele **não** protege contra:

1. **Malware ativo na sua sessão** — keylogger captura a senha mestre; um
   processo com permissão de depuração lê a DEK da memória do Python. O
   interpretador não oferece memória bloqueada (`mlock`) nem garante que a
   string da senha não foi copiada pelo coletor de lixo.
2. **Captura da área de transferência** — qualquer aplicativo pode ler o
   *clipboard* durante os segundos em que a senha está lá.
3. **Perda da senha mestre** — não existe recuperação. É uma consequência do
   desenho (a chave deriva só dela), não uma limitação a corrigir.
4. **Sistema comprometido no boot** (rootkit, firmware) ou disco não cifrado
   apreendido com a máquina ligada e destravada.
5. **Ataque de força bruta offline com hardware ilimitado contra uma senha
   mestre fraca.** O Argon2id encarece cada tentativa, mas não substitui uma
   frase-senha longa. Por isso o app **recusa** senhas mestre com menos de
   12 caracteres ou menos de 60 bits de entropia.
6. **Adulteração do contador de tentativas** — quem tem acesso ao disco pode
   apagar `state.json`. Esse controle protege contra alguém no teclado, não
   contra análise forense do arquivo.

---

## 6. Recomendações ao usuário

1. Use uma **frase-senha** de 5+ palavras como senha mestre (o app gera uma).
2. Ative **criptografia de disco** do sistema (BitLocker, FileVault, LUKS).
3. Exporte um `.ikbak` periodicamente e guarde-o **fora** da máquina.
4. Rode a **auditoria** do cofre pelo menos uma vez por mês.
5. Guarde segredos TOTP no cofre apenas se aceitar que 1º e 2º fator passam a
   ficar no mesmo lugar — é uma troca consciente entre praticidade e
   compartimentação.

---

## 7. Relato de vulnerabilidades

Encontrou um problema? Abra uma *issue* descrevendo o impacto e como reproduzir.
Não inclua o seu `config.json`, o `ironkeypy.db` nem capturas com dados reais.
