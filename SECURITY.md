# Modelo de Segurança — IronKey Py 2.1

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

O vazamento de metadados da v1 era grave por si só: a lista de serviços em que
a vítima tem conta, com os respectivos logins, é insumo direto para phishing
dirigido e *credential stuffing* — mesmo sem nenhuma senha.

Ainda são observáveis por quem tiver o arquivo: **quantos** registros existem e
**quando** foram criados/alterados. Ocultar isso exigiria preenchimento
artificial, com custo desproporcional para a ameaça.

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

---

## Sincronização entre dispositivos (2.1)

O cofre passa a poder existir em mais de uma máquina. Isso muda a superfície de
risco, e as decisões abaixo existem para que a mudança seja **contida**:

### O que o provedor de nuvem vê

| Vê | Não vê |
|---|---|
| O tamanho do arquivo cifrado | Senha mestre, KEK, DEK |
| Horário de cada sincronização | Títulos, usuários, senhas, URLs, notas, TOTP |
| Um identificador aleatório do cofre (`vault_id`) | Quantidade de registros |
| Rótulo e identificador do dispositivo que gravou | Qualquer campo do cofre, em claro ou decifrável |

O identificador do cofre e o rótulo do dispositivo ficam **em texto claro** no
manifesto, de propósito: o manifesto é um oráculo de completude (é lido antes de
decifrar qualquer coisa) e precisa ser verificável. Por isso ele é autenticado por
HMAC-SHA256 — adulterar `payload_bytes` ou `payload_sha256` para forçar a leitura
de lixo é detectado e o arquivo é ignorado.

Ser honesto sobre isso importa: habilitar sincronização **não** é gratuito em
privacidade. O que ela não faz é expor o conteúdo.

### Por que o arquivo de entrada (`.ikenr`) não fica na pasta de sincronização

O `.ikbak` (backup) restaura dados, mas cria um cofre **novo** — com outra DEK e,
portanto, outra chave de sincronização. Para dois dispositivos compartilharem o
mesmo cofre é preciso transferir o **cabeçalho** do cofre (KDF, `vault_id`, DEK
embrulhada pela KEK). Esse é o arquivo `.ikenr`, protegido pela senha mestre.

Ele é transferido **uma vez, fora do armazenamento em nuvem**. Guardá-lo junto do
cofre daria a quem obtivesse acesso ao provedor, de uma só vez, o ciphertext do
cofre *e* o material para ataque de dicionário offline contra a senha mestre —
exposição que hoje existe apenas na máquina do usuário. Ao usar, o arquivo deve ser
apagado.

### Exclusão: por que "apagar" deixou de ser `DELETE`

Com dois dispositivos, apagar a linha do banco faria o registro **ressuscitar** no
outro dispositivo (que nunca soube da exclusão). Exclusão virou um fato versionado
(*tombstone*), e o conteúdo é apagado **no mesmo instante** — só o título permanece,
para que o usuário reconheça o registro ao revisar um conflito. O histórico de
senhas daquele registro é descartado imediatamente.

As marcas de exclusão ficam no arquivo de sincronização por até 90 dias
(configurável, com teto rígido). É uma decisão consciente de retenção: sem isso, a
exclusão não se propaga. Um dispositivo que fique mais tempo sem sincronizar pode
reintroduzir um registro excluído — o aplicativo detecta e avisa.

### Conflitos nunca são resolvidos em silêncio

Se o mesmo registro é alterado nos dois dispositivos, **as duas versões
sobrevivem**: a mais recente mantém o registro original e a outra vira um registro
novo com "conflito" no título, listado no diálogo de conflitos. Descartar uma das
versões sem avisar poderia custar um acesso — e é exatamente o tipo de falha que
não se deve cometer num gerenciador de senhas.

### Limites reconhecidos

- **Não há revogação de dispositivo.** Um segundo dispositivo que já tem a DEK
  continua com acesso até que a DEK seja rotacionada (e a rotação exige reescrever
  o arquivo de sincronização do zero).
- **Rotação de DEK não é exposta na interface** nesta versão; a falha é detectada
  (erro de autenticação) em vez de silenciosa.
- **Não há sincronização em tempo real**: a latência é a do cliente de nuvem.
- **O canal depende do provedor de nuvem** escolhido pelo usuário. O conteúdo é
  cifrado ponta a ponta, mas disponibilidade e versões antigas do arquivo são
  responsabilidade dele — por isso o app detecta regressão de geração e reenvia.
