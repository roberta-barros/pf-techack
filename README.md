# PhishGuard B — Detector de Phishing (Conceito B)

Projeto pronto para atender **Opção 3 (Ferramenta para detecção de Phishing) – Conceito B**.

## O que cobre
- **C (Nota C)**: checagem em lista (OpenPhish), heurísticas simples (números/letras, subdomínios, caracteres especiais) e **UI web básica**.
- **B (Nota B)**: + WHOIS (idade do domínio), detecção de **DNS dinâmico**, análise de **SSL/TLS** (emissor, expiração, hostname), **redirecionamentos**, similaridade com **marcas** por **Levenshtein**, e **análise de conteúdo** (forms de login / palavras sensíveis). Interface com **histórico + export CSV** e explicações dos achados.

> Observação: a consulta a **OpenPhish** usa o feed público. Se quiser incluir **PhishTank** ou **Google Safe Browsing**, adicione a lógica em `checks.py` usando as APIs com chave.

## Como rodar
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
# Acesse http://localhost:8000
```

## Arquitetura
- `app.py`: Flask + rotas + SQLite (histórico e export)
- `checks.py`: TODA a análise (listas, heurísticas, WHOIS, SSL, redirects, similaridade, conteúdo, score)
- `brands.txt`: lista de domínios de marcas (edite à vontade)
- `templates/`: páginas Jinja (index, detail, history)
- `requirements.txt`: dependências

## Entrega e Relatório
- Faça **prints**: index com envio de URL, detalhe com explicações/flags, histórico e export CSV.
- Explique os **critérios do score** (no código `compute_score` já documentado).
- Cite limitações (ex.: APIs com chave, conteúdo dinâmico/JS, CAPTCHAs, anti-bot).

Boa sorte! 🎯
