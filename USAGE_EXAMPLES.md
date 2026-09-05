# Exemplos de Uso — IronKey Py

Guia prático das operações do dia a dia.

---

## 1. Primeiro uso: criando o cofre

Ao abrir o programa pela primeira vez, você define a **senha mestre**. Ela
protege todo o resto e **não pode ser recuperada**.

Exigências: mínimo de 12 caracteres **e** 60 bits de entropia.

### A melhor escolha: uma frase-senha

Clique em **"Sugerir frase-senha forte"**. O programa gera algo como:

```
Tordo-Cravo-Vinte-Marfim-Bússola
```

Cinco palavras sorteadas de uma lista de 1.184 termos ≈ **51 bits** só do
sorteio, mais os separadores e maiúsculas. É muito mais fácil de memorizar do
que `X9#mK2$pL@4vN8` e igualmente difícil de quebrar.

> ⚠️ Escreva a senha mestre em papel e guarde num lugar seguro **antes** de
> começar a usar o cofre. Não existe "esqueci minha senha".

---

## 2. Guardando uma credencial

`Ctrl+N` ou botão **"+ Novo"**:

| Campo | Exemplo | Observação |
|---|---|---|
| Serviço / Site | `GitHub` | obrigatório |
| Usuário / E-mail | `wilsondesouza` | |
| URL | `https://github.com` | a auditoria avisa se for `http://` |
| Senha | *(clique em "Gerar senha")* | obrigatório |
| TOTP | `JBSWY3DPEHPK3PXP` | o segredo que o site mostra junto do QR Code |
| Categoria | `Trabalho` | sugere categorias já usadas |
| Notas | `Recuperação: chave em papel no cofre` | cifradas como o resto |

Todos os campos são cifrados com AES-256-GCM antes de tocar o disco.

---

## 3. Usando os códigos 2FA

Se o registro tiver um segredo TOTP, o código de 6 dígitos aparece no card com
a contagem regressiva:

```
GitHub    Trabalho    ● Muito Forte
wilsondesouza
••••••••••••  ◉   477 802 (14s)  ❐
```

Clique no ícone ao lado para copiar. O código é calculado localmente pelo
algoritmo RFC 6238 — sem internet, sem servidor.

> Guardar senha e 2FA no mesmo cofre é uma troca consciente: mais praticidade,
> menos compartimentação. Se o 2FA de contas críticas (banco, e-mail principal)
> puder ficar em um aplicativo separado, prefira assim.

---

## 4. Auditoria: o recurso que mais evita invasão

Aba **Auditoria** → **"Analisar agora"**.

```
Pontuação: 67/100   ·   4 crítico(s)   ·   1 aviso(s)

CRÍTICOS
  Nubank — Senha reutilizada
    A mesma senha é usada em: Nubank, Gmail. Um vazamento em qualquer um
    desses serviços compromete todos os outros.                    [Corrigir]

  Nubank — Senha muito fraca
    21 bits de entropia (quebra estimada: instantâneo).
    Contém termo previsível: "123".                                [Corrigir]

AVISOS
  Nubank — URL sem HTTPS
    "http://nubank.com.br" usa HTTP. Credenciais enviadas a esse
    endereço trafegam sem criptografia.                            [Corrigir]
```

Marque **"Consultar vazamentos (online)"** para também checar cada senha contra
o Have I Been Pwned. A consulta usa *k-anonymity*: apenas os **5 primeiros
caracteres** do SHA-1 da senha saem da sua máquina — nem a senha, nem o hash
completo.

Meta prática: rode a auditoria uma vez por mês e trate primeiro os itens
**reutilizada** e **vazada**, que são os que efetivamente causam invasão.

---

## 5. Backup (faça isso hoje)

**Exportar backup** → escolha uma senha para o arquivo → salva um `.ikbak`.

```
meu-cofre-2026-09-04.ikbak
├─ magic + versão
├─ parâmetros de KDF + salt próprios   ← por isso é portátil
└─ AES-256-GCM( gzip( registros ) )
```

O arquivo é autocontido: restaura em qualquer computador, com a senha do
backup, sem depender do `config.json` original.

**Importar backup** valida o arquivo inteiro antes de mexer no cofre e faz
*merge* — nada é apagado.

Rotina sugerida: um `.ikbak` por mês, guardado em pendrive ou nuvem. Como o
conteúdo já está cifrado, subir para a nuvem é aceitável — desde que a senha do
backup seja forte e diferente da senha mestre.

---

## 6. Migrando de outro gerenciador

**Importar CSV** aceita os formatos de exportação de:

| Origem | Cabeçalhos reconhecidos |
|---|---|
| Bitwarden | `name, login_uri, login_username, login_password, notes, folder` |
| LastPass | `url, username, password, extra, name, grouping` |
| Chrome / Edge | `name, url, username, password` |
| KeePass | `Account, Login Name, Password, Web Site, Comments` |

Depois de importar: **apague o CSV com segurança** — ele é texto puro.

```bash
# Linux/macOS
shred -u senhas-exportadas.csv
```

---

## 7. Trocando a senha mestre

**"Alterar senha mestre"** no rodapé. A operação é instantânea mesmo com
milhares de registros: graças ao envelope KEK/DEK, apenas a chave de dados
(32 bytes) é reembrulhada — o cofre inteiro não precisa ser reescrito.

Troque a senha mestre se: você a digitou em uma máquina que não confia, ela
apareceu em algum vazamento, ou alguém pode tê-la visto.

---

## 8. Vindo da versão 1.x

Basta abrir a nova versão com a senha mestre antiga. Na primeira abertura o
programa:

1. copia `ironkeypy.db` para `ironkeypy.db.v1-<data>.bak` (rede de segurança);
2. decifra cada registro com a chave antiga e recifra em AES-256-GCM;
3. **remove a tabela antiga** e roda `VACUUM` — na v1, nome do site e usuário
   ficavam em texto puro dentro do `.db`;
4. reembrulha a chave com Argon2id.

Confira se está tudo certo e então **apague o arquivo `.bak`** — ele ainda
contém os metadados em texto puro.

---

## 💡 Boas práticas

### ✅ Faça
1. Uma senha **única** por serviço — é o único hábito que impede o efeito dominó.
2. Frase-senha longa para a senha mestre; senha aleatória de 16+ caracteres para o resto.
3. Ative o 2FA em tudo que permitir.
4. Rode a auditoria mensalmente.
5. Mantenha um `.ikbak` fora da máquina.
6. Cifre o disco do sistema (BitLocker / FileVault / LUKS).

### ❌ Não faça
1. Reutilizar a senha mestre em outro lugar.
2. Guardar a senha mestre em um arquivo `.txt` ou em outro gerenciador.
3. Deixar exportações CSV pela pasta de Downloads.
4. Usar o cofre em computador público ou compartilhado.
5. Ignorar avisos de vazamento — trocar a senha leva 30 segundos.

---

## 🧪 Senhas para testar a verificação de vazamento

Estas **aparecem** como comprometidas (nunca use de verdade):

```
password    123456    qwerty    abc123    letmein    senha123
```

Estas, geradas pelo programa, não aparecem:

```
tpSGb%8c!=#7VmxK_8F-
Tordo-Cravo-Vinte-Marfim-Bússola
```

---

## 🆘 Problemas comuns

| Sintoma | Causa provável | Solução |
|---|---|---|
| "Senha mestre incorreta" com a senha certa | teclado em outro layout, Caps Lock | use o botão 👁 para conferir o que digitou |
| "Aguarde N s" ao destravar | limite de tentativas ativado | espere; a espera cresce a cada erro |
| A janela não abre em Linux | Tk ausente | `sudo apt install python3-tk` |
| Verificação de vazamento falha | sem internet ou proxy | é opcional; o cofre funciona offline |
| Perdi a senha mestre | — | não há recuperação; restaure de um `.ikbak` cuja senha você lembre |
