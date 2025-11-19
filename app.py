from flask import Flask, render_template, request, jsonify, send_file
import re
import ssl
import socket
import whois
import requests
from urllib.parse import urlparse
from datetime import datetime
import json
import csv
import io
import sqlite3
import os
def levenshtein_distance(s1, s2):
    """Implementação pura em Python da distância de Levenshtein"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

app = Flask(__name__)

# Configuração do banco de dados
DATABASE = 'phishing_history.db'

def get_db():
    """Obtém conexão com o banco de dados"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializa o banco de dados com as tabelas necessárias"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Tabela principal de análises
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            overall_risk_score REAL NOT NULL,
            overall_status TEXT NOT NULL,
            recommendation TEXT NOT NULL
        )
    ''')
    
    # Tabela de detalhes das verificações
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            check_name TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            FOREIGN KEY (analysis_id) REFERENCES analyses (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"[Database] Banco de dados '{DATABASE}' inicializado com sucesso!")

def save_analysis(results):
    """Salva uma análise no banco de dados"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Insere a análise principal
    cursor.execute('''
        INSERT INTO analyses (url, domain, timestamp, overall_risk_score, overall_status, recommendation)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        results['url'],
        results['domain'],
        results['timestamp'],
        results['overall_risk_score'],
        results['overall_status'],
        results['recommendation']
    ))
    
    analysis_id = cursor.lastrowid
    
    # Insere os detalhes de cada verificação
    for check in results['checks']:
        cursor.execute('''
            INSERT INTO checks (analysis_id, check_name, status, details, risk_score)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            analysis_id,
            check['check'],
            check['status'],
            check['details'],
            check['risk_score']
        ))
    
    conn.commit()
    conn.close()
    
    return analysis_id

def get_all_analyses():
    """Recupera todas as análises do banco de dados"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, url, domain, timestamp, overall_risk_score, overall_status, recommendation
        FROM analyses
        ORDER BY id DESC
    ''')
    
    analyses = []
    for row in cursor.fetchall():
        analysis = {
            'id': row['id'],
            'url': row['url'],
            'domain': row['domain'],
            'timestamp': row['timestamp'],
            'overall_risk_score': row['overall_risk_score'],
            'overall_status': row['overall_status'],
            'recommendation': row['recommendation'],
            'checks': []
        }
        
        # Busca os checks dessa análise
        cursor.execute('''
            SELECT check_name, status, details, risk_score
            FROM checks
            WHERE analysis_id = ?
        ''', (row['id'],))
        
        for check_row in cursor.fetchall():
            analysis['checks'].append({
                'check': check_row['check_name'],
                'status': check_row['status'],
                'details': check_row['details'],
                'risk_score': check_row['risk_score']
            })
        
        analyses.append(analysis)
    
    conn.close()
    return analyses

def get_statistics_from_db():
    """Calcula estatísticas a partir do banco de dados"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Contagem total e por status
    cursor.execute('SELECT COUNT(*) FROM analyses')
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM analyses WHERE overall_status = 'safe'")
    safe = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM analyses WHERE overall_status = 'warning'")
    warning = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM analyses WHERE overall_status = 'danger'")
    danger = cursor.fetchone()[0]
    
    # Média de risco
    cursor.execute('SELECT AVG(overall_risk_score) FROM analyses')
    avg_risk = cursor.fetchone()[0] or 0
    
    # Distribuição por tipo de verificação
    check_distribution = {}
    cursor.execute('SELECT DISTINCT check_name FROM checks')
    check_names = [row[0] for row in cursor.fetchall()]
    
    for check_name in check_names:
        check_distribution[check_name] = {'safe': 0, 'warning': 0, 'danger': 0, 'unknown': 0}
        
        for status in ['safe', 'warning', 'danger', 'unknown']:
            cursor.execute('''
                SELECT COUNT(*) FROM checks 
                WHERE check_name = ? AND status = ?
            ''', (check_name, status))
            check_distribution[check_name][status] = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'total_analyzed': total,
        'safe': safe,
        'warning': warning,
        'danger': danger,
        'avg_risk': round(avg_risk, 1),
        'check_distribution': check_distribution
    }

# Inicializa o banco de dados ao iniciar
init_db()

# Marcas conhecidas para verificação de similaridade
KNOWN_BRANDS = [
    'google', 'facebook', 'apple', 'microsoft', 'amazon', 'netflix', 'paypal',
    'instagram', 'twitter', 'linkedin', 'whatsapp', 'youtube', 'spotify',
    'dropbox', 'adobe', 'ebay', 'yahoo', 'outlook', 'office365', 'icloud',
    'bancodobrasil', 'itau', 'bradesco', 'santander', 'caixa', 'nubank',
    'mercadolivre', 'americanas', 'magazineluiza', 'casasbahia'
]

# Provedores de DNS dinâmico
DYNAMIC_DNS_PROVIDERS = [
    'no-ip', 'dyndns', 'dynu', 'afraid', 'duckdns', 'noip', 'freedns',
    'changeip', 'dnsdynamic', 'dtdns', 'yi.org', 'dyn.com'
]

# Listas de phishing conhecidas (simulado - em produção usaria APIs reais)
KNOWN_PHISHING_DOMAINS = [
    'secure-paypal-login.com', 'facebook-security.net', 'apple-id-verify.com'
]

# Cache para o feed do OpenPhish
openphish_cache = {
    'urls': set(),
    'last_update': None
}


def fetch_openphish_feed():
    """Busca a lista atualizada do OpenPhish"""
    global openphish_cache
    
    try:
        # Atualiza o cache a cada 1 hora
        now = datetime.now()
        if (openphish_cache['last_update'] is None or 
            (now - openphish_cache['last_update']).seconds > 3600):
            
            response = requests.get(
                'https://openphish.com/feed.txt',
                timeout=10,
                headers={'User-Agent': 'PhishingDetector/1.0'}
            )
            
            if response.status_code == 200:
                urls = set(response.text.strip().split('\n'))
                openphish_cache['urls'] = urls
                openphish_cache['last_update'] = now
                print(f"[OpenPhish] Feed atualizado: {len(urls)} URLs carregadas")
            
    except Exception as e:
        print(f"[OpenPhish] Erro ao buscar feed: {e}")
    
    return openphish_cache['urls']


def check_known_phishing_lists(domain):
    """Verifica se o domínio está em listas de phishing conhecidas"""
    result = {
        'check': 'Lista de Phishing (OpenPhish)',
        'status': 'safe',
        'details': 'Domínio não encontrado em listas de phishing conhecidas',
        'risk_score': 0
    }
    
    # Busca o feed do OpenPhish
    openphish_urls = fetch_openphish_feed()
    
    # Verifica se o domínio ou URL está na lista
    found_in_openphish = False
    for phish_url in openphish_urls:
        if domain in phish_url:
            found_in_openphish = True
            break
    
    if found_in_openphish:
        result['status'] = 'danger'
        result['details'] = f'⚠️ ALERTA: Domínio encontrado no feed OpenPhish!'
        result['risk_score'] = 100
    elif domain in KNOWN_PHISHING_DOMAINS:
        result['status'] = 'danger'
        result['details'] = 'Domínio encontrado em lista local de phishing'
        result['risk_score'] = 100
    else:
        # Mostra quantas URLs foram verificadas
        num_urls = len(openphish_urls)
        if num_urls > 0:
            result['details'] = f'Verificado contra {num_urls} URLs do OpenPhish - Não encontrado'
        else:
            result['details'] = 'Feed OpenPhish indisponível - Verificação local apenas'
            result['risk_score'] = 10
    
    return result


def extract_domain(url):
    """Extrai o domínio de uma URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except:
        return url.lower()


def check_suspicious_patterns(domain):
    """Verifica padrões suspeitos na URL"""
    issues = []
    risk_score = 0
    
    # Números substituindo letras (l33t speak)
    leet_patterns = {'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't'}
    for num, letter in leet_patterns.items():
        if num in domain:
            issues.append(f"Número '{num}' pode estar substituindo '{letter}'")
            risk_score += 15
    
    # Excesso de subdomínios
    subdomain_count = domain.count('.')
    if subdomain_count > 3:
        issues.append(f"Excesso de subdomínios ({subdomain_count})")
        risk_score += 20
    
    # Caracteres especiais suspeitos
    suspicious_chars = ['-', '_', '@']
    for char in suspicious_chars:
        count = domain.count(char)
        if count > 2:
            issues.append(f"Uso excessivo de '{char}' ({count} vezes)")
            risk_score += 10
    
    # URL muito longa
    if len(domain) > 50:
        issues.append(f"Domínio muito longo ({len(domain)} caracteres)")
        risk_score += 15
    
    return {
        'check': 'Padrões Suspeitos',
        'status': 'danger' if risk_score > 30 else 'warning' if risk_score > 0 else 'safe',
        'details': '; '.join(issues) if issues else 'Nenhum padrão suspeito detectado',
        'risk_score': min(risk_score, 100)
    }


def check_domain_age(domain):
    """Analisa a idade do domínio via WHOIS"""
    result = {
        'check': 'Idade do Domínio',
        'status': 'unknown',
        'details': 'Não foi possível obter informações WHOIS',
        'risk_score': 30,
        'age_days': None
    }
    
    try:
        # Remove subdomínios para consulta WHOIS
        parts = domain.split('.')
        if len(parts) > 2:
            main_domain = '.'.join(parts[-2:])
        else:
            main_domain = domain
        
        w = whois.whois(main_domain)
        
        if w.creation_date:
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            age = (datetime.now() - creation_date).days
            result['age_days'] = age
            
            if age < 30:
                result['status'] = 'danger'
                result['details'] = f'Domínio muito novo: {age} dias'
                result['risk_score'] = 80
            elif age < 180:
                result['status'] = 'warning'
                result['details'] = f'Domínio relativamente novo: {age} dias'
                result['risk_score'] = 40
            else:
                result['status'] = 'safe'
                result['details'] = f'Domínio estabelecido: {age} dias'
                result['risk_score'] = 0
    except Exception as e:
        result['details'] = f'Erro na consulta WHOIS: {str(e)}'
    
    return result


def check_dynamic_dns(domain):
    """Verifica se o domínio usa DNS dinâmico"""
    result = {
        'check': 'DNS Dinâmico',
        'status': 'safe',
        'details': 'Não utiliza provedores de DNS dinâmico conhecidos',
        'risk_score': 0
    }
    
    domain_lower = domain.lower()
    for provider in DYNAMIC_DNS_PROVIDERS:
        if provider in domain_lower:
            result['status'] = 'warning'
            result['details'] = f'Utiliza provedor de DNS dinâmico: {provider}'
            result['risk_score'] = 50
            break
    
    return result


def check_ssl_certificate(domain):
    """Analisa o certificado SSL do domínio"""
    result = {
        'check': 'Certificado SSL',
        'status': 'unknown',
        'details': 'Não foi possível verificar o certificado SSL',
        'risk_score': 30,
        'cert_info': {}
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extrai informações do certificado
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                
                # Data de expiração
                not_after = cert.get('notAfter', '')
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_to_expiry = (expiry_date - datetime.now()).days
                
                result['cert_info'] = {
                    'issuer': issuer.get('organizationName', 'Desconhecido'),
                    'subject': subject.get('commonName', 'Desconhecido'),
                    'expiry_date': not_after,
                    'days_to_expiry': days_to_expiry
                }
                
                issues = []
                risk = 0
                
                # Verifica coincidência entre domínio e certificado
                cert_cn = subject.get('commonName', '').lower()
                san = cert.get('subjectAltName', [])
                san_domains = [name for type_, name in san if type_ == 'DNS']
                
                domain_match = (
                    domain in cert_cn or 
                    cert_cn.replace('*.', '') in domain or
                    any(domain in d or d.replace('*.', '') in domain for d in san_domains)
                )
                
                if not domain_match:
                    issues.append('Domínio não coincide com certificado')
                    risk += 60
                
                # Verifica se certificado está expirando
                if days_to_expiry < 0:
                    issues.append('Certificado expirado!')
                    risk += 70
                elif days_to_expiry < 30:
                    issues.append(f'Certificado expira em {days_to_expiry} dias')
                    risk += 20
                
                # Verifica emissor
                issuer_name = issuer.get('organizationName', '').lower()
                trusted_issuers = ['digicert', 'let\'s encrypt', 'comodo', 'godaddy', 'globalsign']
                if not any(ti in issuer_name for ti in trusted_issuers):
                    issues.append(f'Emissor não comum: {issuer_name}')
                    risk += 15
                
                if risk == 0:
                    result['status'] = 'safe'
                    result['details'] = 'Certificado SSL válido e confiável'
                    result['risk_score'] = 0
                else:
                    result['status'] = 'danger' if risk > 50 else 'warning'
                    result['details'] = '; '.join(issues)
                    result['risk_score'] = min(risk, 100)
                    
    except ssl.SSLError as e:
        result['status'] = 'danger'
        result['details'] = f'Erro SSL: {str(e)}'
        result['risk_score'] = 70
    except socket.timeout:
        result['details'] = 'Timeout ao conectar'
        result['risk_score'] = 40
    except Exception as e:
        result['details'] = f'Sem HTTPS ou erro: {str(e)}'
        result['risk_score'] = 50
    
    return result


def check_redirects(url):
    """Detecta redirecionamentos suspeitos"""
    result = {
        'check': 'Redirecionamentos',
        'status': 'unknown',
        'details': 'Não foi possível verificar redirecionamentos',
        'risk_score': 20,
        'redirect_chain': []
    }
    
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        response = requests.get(url, allow_redirects=True, timeout=10, 
                               headers={'User-Agent': 'Mozilla/5.0'})
        
        redirect_chain = [r.url for r in response.history]
        redirect_chain.append(response.url)
        result['redirect_chain'] = redirect_chain
        
        num_redirects = len(response.history)
        
        if num_redirects == 0:
            result['status'] = 'safe'
            result['details'] = 'Sem redirecionamentos'
            result['risk_score'] = 0
        elif num_redirects <= 2:
            result['status'] = 'safe'
            result['details'] = f'{num_redirects} redirecionamento(s) - normal'
            result['risk_score'] = 5
        elif num_redirects <= 4:
            result['status'] = 'warning'
            result['details'] = f'{num_redirects} redirecionamentos - suspeito'
            result['risk_score'] = 40
        else:
            result['status'] = 'danger'
            result['details'] = f'{num_redirects} redirecionamentos - muito suspeito!'
            result['risk_score'] = 70
            
        # Verifica se redireciona para domínio diferente
        if redirect_chain:
            original_domain = extract_domain(redirect_chain[0])
            final_domain = extract_domain(redirect_chain[-1])
            if original_domain != final_domain:
                result['status'] = 'warning'
                result['details'] += f' | Redireciona de {original_domain} para {final_domain}'
                result['risk_score'] = min(result['risk_score'] + 30, 100)
                
    except requests.Timeout:
        result['details'] = 'Timeout ao acessar URL'
    except Exception as e:
        result['details'] = f'Erro: {str(e)}'
    
    return result


def check_brand_similarity(domain):
    """Verifica similaridade com marcas conhecidas usando Levenshtein"""
    result = {
        'check': 'Similaridade com Marcas',
        'status': 'safe',
        'details': 'Domínio não é similar a marcas conhecidas',
        'risk_score': 0,
        'similar_brands': []
    }
    
    # Remove TLD e subdomínios para comparação
    parts = domain.split('.')
    main_part = parts[0] if len(parts) > 0 else domain
    
    similar = []
    for brand in KNOWN_BRANDS:
        dist = levenshtein_distance(main_part.lower(), brand.lower())
        # Se a distância for pequena mas não zero, pode ser typosquatting
        if 0 < dist <= 3 and len(main_part) >= len(brand) - 2:
            similarity = 1 - (dist / max(len(main_part), len(brand)))
            if similarity > 0.6:
                similar.append({
                    'brand': brand,
                    'distance': dist,
                    'similarity': round(similarity * 100, 1)
                })
    
    if similar:
        similar.sort(key=lambda x: x['distance'])
        result['similar_brands'] = similar
        
        if similar[0]['similarity'] > 85:
            result['status'] = 'danger'
            result['details'] = f"Muito similar a '{similar[0]['brand']}' ({similar[0]['similarity']}%)"
            result['risk_score'] = 80
        else:
            result['status'] = 'warning'
            brands_str = ', '.join([f"{s['brand']} ({s['similarity']}%)" for s in similar[:3]])
            result['details'] = f'Similar a: {brands_str}'
            result['risk_score'] = 50
    
    return result


def check_content_analysis(url):
    """Analisa o conteúdo da página para detectar formulários de login"""
    result = {
        'check': 'Análise de Conteúdo',
        'status': 'unknown',
        'details': 'Não foi possível analisar o conteúdo',
        'risk_score': 20,
        'findings': []
    }
    
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        response = requests.get(url, timeout=10, 
                               headers={'User-Agent': 'Mozilla/5.0'})
        content = response.text.lower()
        
        findings = []
        risk = 0
        
        # Detecta formulários de login
        if '<form' in content:
            if any(term in content for term in ['password', 'senha', 'pwd']):
                findings.append('Formulário com campo de senha detectado')
                risk += 30
            
            if any(term in content for term in ['login', 'signin', 'sign-in', 'entrar']):
                findings.append('Formulário de login detectado')
                risk += 20
        
        # Detecta solicitação de informações sensíveis
        sensitive_terms = [
            ('cpf', 'CPF'),
            ('credit', 'Cartão de crédito'),
            ('cartao', 'Cartão'),
            ('social security', 'SSN'),
            ('cvv', 'CVV'),
            ('bank account', 'Conta bancária'),
            ('conta bancaria', 'Conta bancária')
        ]
        
        for term, label in sensitive_terms:
            if term in content:
                findings.append(f'Solicitação de {label}')
                risk += 25
        
        # Verifica termos de urgência (comum em phishing)
        urgency_terms = [
            'urgent', 'urgente', 'immediately', 'imediatamente',
            'suspended', 'suspens', 'locked', 'bloquead',
            'verify now', 'verifique agora', 'act now'
        ]
        
        urgency_count = sum(1 for term in urgency_terms if term in content)
        if urgency_count > 0:
            findings.append(f'{urgency_count} termos de urgência detectados')
            risk += urgency_count * 10
        
        result['findings'] = findings
        
        if risk == 0:
            result['status'] = 'safe'
            result['details'] = 'Nenhum indicador suspeito no conteúdo'
            result['risk_score'] = 0
        else:
            result['status'] = 'danger' if risk > 50 else 'warning'
            result['details'] = '; '.join(findings)
            result['risk_score'] = min(risk, 100)
            
    except requests.Timeout:
        result['details'] = 'Timeout ao acessar URL'
    except Exception as e:
        result['details'] = f'Erro ao analisar conteúdo: {str(e)}'
    
    return result


def analyze_url(url):
    """Executa todas as análises em uma URL"""
    domain = extract_domain(url)
    
    results = {
        'url': url,
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'checks': []
    }
    
    # Executa todas as verificações
    results['checks'].append(check_known_phishing_lists(domain))
    results['checks'].append(check_suspicious_patterns(domain))
    results['checks'].append(check_domain_age(domain))
    results['checks'].append(check_dynamic_dns(domain))
    results['checks'].append(check_ssl_certificate(domain))
    results['checks'].append(check_redirects(url))
    results['checks'].append(check_brand_similarity(domain))
    results['checks'].append(check_content_analysis(url))
    
    # Calcula score geral de risco
    total_risk = sum(check['risk_score'] for check in results['checks'])
    avg_risk = total_risk / len(results['checks'])
    
    # Verifica se há alertas críticos (qualquer check com score >= 70)
    critical_alerts = [check for check in results['checks'] if check['risk_score'] >= 70]
    high_alerts = [check for check in results['checks'] if 50 <= check['risk_score'] < 70]
    
    # Se houver alertas críticos, o score final deve refletir isso
    if critical_alerts:
        # Usa o maior score crítico como base, com peso maior
        max_critical = max(check['risk_score'] for check in critical_alerts)
        final_risk = max(avg_risk, max_critical * 0.8)  # No mínimo 80% do alerta crítico
    elif high_alerts:
        # Se houver alertas altos, aumenta o score
        max_high = max(check['risk_score'] for check in high_alerts)
        final_risk = max(avg_risk, max_high * 0.6)  # No mínimo 60% do alerta alto
    else:
        final_risk = avg_risk
    
    results['overall_risk_score'] = round(final_risk, 1)
    
    if final_risk < 20:
        results['overall_status'] = 'safe'
        results['recommendation'] = 'URL parece segura'
    elif final_risk < 50:
        results['overall_status'] = 'warning'
        results['recommendation'] = 'URL possui alguns indicadores suspeitos - proceda com cautela'
    else:
        results['overall_status'] = 'danger'
        results['recommendation'] = 'URL altamente suspeita - evite acessar!'
    
    # Salva no banco de dados
    save_analysis(results)
    
    return results


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL não fornecida'}), 400
    
    results = analyze_url(url)
    return jsonify(results)


@app.route('/history')
def get_history():
    analyses = get_all_analyses()
    return jsonify(analyses)


@app.route('/export')
def export_history():
    analyses = get_all_analyses()
    
    if not analyses:
        return jsonify({'error': 'Nenhum histórico para exportar'}), 400
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Cabeçalho
    writer.writerow(['ID', 'URL', 'Domínio', 'Data/Hora', 'Score de Risco', 'Status', 'Recomendação'])
    
    # Dados
    for entry in analyses:
        writer.writerow([
            entry['id'],
            entry['url'],
            entry['domain'],
            entry['timestamp'],
            entry['overall_risk_score'],
            entry['overall_status'],
            entry['recommendation']
        ])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='phishing_analysis_history.csv'
    )


@app.route('/statistics')
def get_statistics():
    stats = get_statistics_from_db()
    return jsonify(stats)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
