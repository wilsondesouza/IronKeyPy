# Exemplos de Uso - IronKey Py

## 🔍 Testando a Verificação de Senhas Comprometidas

### Senhas que DEVEM aparecer como comprometidas (para teste):

```
password
123456
qwerty
abc123
letmein
welcome
monkey
```

**NUNCA USE ESSAS SENHAS!** Elas estão entre as mais comprometidas do mundo.

### Senhas que provavelmente NÃO aparecerão (geradas pelo IronKey Py):

```
X9#mK2$pL@4vN8
Qw3!Rt5@Yu7#Io9
Zx2$Cv4&Bn6*Mm8
```

Senhas aleatórias geradas com 12+ caracteres, símbolos, números e letras mistas raramente aparecem em vazamentos.

## 💡 Boas Práticas

### ✅ O que FAZER:

1. **Gerar senhas únicas** para cada site/aplicativo
2. **Usar 16+ caracteres** quando possível
3. **Incluir todos os tipos** de caracteres (maiúsculas, minúsculas, números, símbolos)
4. **Verificar segurança** antes de usar uma senha
5. **Fazer backup** regularmente
6. **Mudar senhas** se alertado de comprometimento

### ❌ O que NÃO fazer:

1. ❌ Reutilizar senhas entre diferentes sites
2. ❌ Usar informações pessoais (nome, data de nascimento, etc.)
3. ❌ Usar palavras do dicionário
4. ❌ Usar sequências (123456, qwerty, abcdef)
5. ❌ Compartilhar sua senha mestre
6. ❌ Ignorar alertas de segurança

## 🎯 Fluxo Recomendado

### Para Novas Senhas:

1. Abra IronKey Py
2. Preencha Site e Usuário
3. Ajuste comprimento para **16+ caracteres**
4. Marque **TODAS as opções** de caracteres
5. Clique "💾 Gerar e Salvar"
6. Opcional: Clique "🔍 Verificar Segurança"
7. Use a senha copiada no site

### Para Senhas Existentes:

Se você já tem senhas salvas em outros lugares:

1. **NÃO** as copie para o IronKey Py
2. Em vez disso, **gere novas senhas** no IronKey Py
3. **Atualize** cada site com a nova senha
4. **Delete** as senhas antigas

### Verificação Periódica:

Recomendo verificar suas senhas salvas a cada 3-6 meses:

1. Vá para "Gerenciar Senhas"
2. Clique "🔍 Verificar" em cada senha
3. Se aparecer alerta, **gere nova senha** imediatamente
4. Atualize no site correspondente

## 🔐 Entendendo os Alertas

### ✅ Senha Segura
```
"✅ Senha segura! Não encontrada em vazamentos conhecidos."
```
**Ação:** Continue usando normalmente.

### ⚠️ Alerta (< 10 aparições)
```
"⚠️ ALERTA: Esta senha apareceu 5x em vazamentos. Considere mudá-la."
```
**Ação:** Troque a senha o mais breve possível.

### 🚨 Perigo (< 100 aparições)
```
"🚨 PERIGO: Esta senha apareceu 47x em vazamentos! Mude IMEDIATAMENTE."
```
**Ação:** Troque AGORA. Esta senha é conhecida por hackers.

### 🔴 Crítico (100+ aparições)
```
"🔴 CRÍTICO: Esta senha apareceu 2,384x em vazamentos! NUNCA use esta senha!"
```
**Ação:** Troque IMEDIATAMENTE e verifique se a conta já foi comprometida.

## 📊 Estatísticas de Segurança

### Força da Senha vs Tempo para Quebrar (força bruta):

| Comprimento | Apenas Letras | + Números | + Símbolos | Tempo para Quebrar |
|-------------|---------------|-----------|------------|-------------------|
| 8 chars     | 2 horas       | 1 dia     | 1 semana   | ⚠️ Fraco         |
| 12 chars    | 2 anos        | 2 séculos | 34 mil anos| ✅ Bom           |
| 16 chars    | 200 mil anos  | 4 milhões | 92 bilhões | ✅ Excelente     |

*Assumindo 100 bilhões de tentativas por segundo (hardware moderno)

## 🆘 Dicas de Emergência

### Se você esquecer a Senha Mestre:

**Infelizmente, NÃO há como recuperar.** Por segurança, não existe backdoor.

**Prevenção:**
- Escreva a senha mestre em papel e guarde em local seguro
- Use uma senha memorável mas forte (exemplo: frase longa)
- Configure recuperação em outro gerenciador como backup

### Se seu computador(armazenamento) for roubado:

Suas senhas estão seguras graças à criptografia, MAS:

1. **Troque todas as senhas** importantes
2. **Habilite 2FA** em todas as contas
3. **Monitore** atividades suspeitas

### Se detectar atividade suspeita:

1. Troque senhas **imediatamente**
2. Habilite 2FA
3. Verifique se outras contas usam a mesma senha
4. Execute verificação completa com "🔍 Verificar" em todas as senhas

## 🔗 Links Úteis

- [Have I Been Pwned](https://haveibeenpwned.com/) - Verifique se seu email foi vazado
- [Password Strength Checker](https://www.passwordmonster.com/) - Teste força de senhas
- [2FA Directory](https://2fa.directory/) - Veja quais sites suportam 2FA
