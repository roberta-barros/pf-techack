# Detector de Phishing

## Análise Heurística Avançada com Interface Web Interativa

## Funcionalidades Implementadas

### Análise Heurística Avançada

**Todas as verificações do Conceito C:**
- Verificação em listas de phishing conhecidas
- Detecção de padrões suspeitos (números substituindo letras, subdomínios excessivos, caracteres especiais)

**Análise de idade do domínio via WHOIS**
- Identifica domínios muito novos (< 30 dias = alto risco)
- Domínios relativamente novos (< 180 dias = risco médio)

**Verificação de DNS dinâmico**
- Detecta uso de provedores como no-ip, dyndns, duckdns, etc.

**Análise de certificados SSL**
- Verifica emissor do certificado
- Data de expiração
- Coincidência entre domínio e certificado

**Detecção de redirecionamentos suspeitos**
- Conta número de redirecionamentos
- Identifica redirecionamentos para domínios diferentes

**Verificação de similaridade com marcas conhecidas**
- Usa distância de Levenshtein
- Detecta typosquatting (ex: paypa1.com, g00gle.com)

**Análise de conteúdo**
- Detecta formulários de login
- Identifica solicitações de informações sensíveis (CPF, cartão, etc.)
- Detecta termos de urgência (comum em phishing)

### Interface Web Interativa

**Dashboard com visualização detalhada**
- Score de risco visual (0-100)
- Indicador colorido (verde/amarelo/vermelho)
- Detalhes de cada verificação

**Histórico de URLs verificadas**
- Lista completa de análises realizadas
- Exportação para CSV

**Gráficos estatísticos**
- Distribuição de URLs por status
- Distribuição por tipo de verificação

**Explicações detalhadas**
- Cada verificação mostra o risco e o motivo
