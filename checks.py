import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import tldextract

DYN_DNS_HOSTS = (
    "no-ip.org","noip.me","hopto.org","zapto.org","sytes.net","duckdns.org",
    "ddns.net","dynu.net","servebeer.com","servehttp.com","changeip.net",
    "myftp.biz","myftp.org","gotdns.ch","homedns.org","dyndns.org","ddnsking.com"
)

SUSPICIOUS_KEYWORDS_PT = {"senha","password","cartão","cartao","cpf","pix","token","banco","login","verificar","atualização","atualizacao"}

def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return url

def get_registered_domain(url: str) -> str:
    u = urlparse(normalize_url(url))
    ext = tldextract.extract(u.hostname or "")
    if ext.registered_domain:
        return ext.registered_domain.lower()
    return (u.hostname or "").lower()

def count_subdomains(url: str) -> int:
    u = urlparse(normalize_url(url))
    ext = tldextract.extract(u.hostname or "")
    sub = ext.subdomain or ""
    return len([s for s in sub.split(".") if s])

def has_special_chars_in_path(url: str) -> bool:
    u = urlparse(normalize_url(url))
    return any(c in (u.path or "") for c in ["@", "%", "\\", "//", "xn--"])

def digits_ratio_in_domain(url: str) -> float:
    u = urlparse(normalize_url(url))
    host = (u.hostname or "").lower()
    letters = sum(ch.isalpha() for ch in host)
    digits = sum(ch.isdigit() for ch in host)
    return (digits / max(1, letters + digits))

def check_openphish(url: str, timeout=7) -> dict:
    try:
        feed = requests.get("https://openphish.com/feed.txt", timeout=timeout).text.splitlines()
        url_norm = normalize_url(url).lower().rstrip("/")
        host = urlparse(url_norm).hostname
        exact = url_norm in [x.lower().rstrip("/") for x in feed]
        by_host = any(urlparse(x).hostname == host for x in feed if x)
        return {"source":"OpenPhish","match_exact": exact, "match_host": by_host, "ok": True}
    except Exception as e:
        return {"source":"OpenPhish","error": str(e), "ok": False}

def fetch_head(url: str, timeout=8):
    try:
        r = requests.get(normalize_url(url), timeout=timeout, allow_redirects=True, headers={"User-Agent":"phishguard-b/1.0"})
        return r
    except Exception as e:
        return e

def check_redirects(url: str, timeout=8):
    r = fetch_head(url, timeout=timeout)
    chain = []
    if isinstance(r, Exception):
        return {"ok": False, "error": str(r), "chain": chain}
    for resp in r.history:
        chain.append(resp.headers.get("Location") or resp.url)
    final_url = r.url
    initial_domain = get_registered_domain(url)
    final_domain = get_registered_domain(final_url)
    cross_domain = (initial_domain != final_domain)
    return {"ok": True, "count": len(chain), "cross_domain": cross_domain, "final_url": final_url, "chain": chain}

from datetime import datetime, timezone
import ssl, socket
from urllib.parse import urlparse

def _parse_cert_time(s: str):
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass
    return None

def _extract_dns_names(cert_dict):
    # 1) subjectAltName (DNS)  2) fallback no CN
    names = [v for k, v in cert_dict.get("subjectAltName", []) if k.lower() == "dns"]
    if not names:
        for tup in cert_dict.get("subject", ()):
            d = dict(tup)
            cn = d.get("commonName")
            if cn:
                names.append(cn)
    return names

def _match_hostname(host: str, names):
    host = host.lower()
    for pattern in (n.lower() for n in names):
        if pattern.startswith("*."):
            suf = pattern[1:]  # ".badssl.com"
            if host.endswith(suf) and host.count(".") >= suf.count(".")+1:
                return True
        if host == pattern:
            return True
    return False

from datetime import datetime, timezone
import ssl, socket
from urllib.parse import urlparse

def _parse_cert_time(s: str):
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass
    return None

def _extract_dns_names(cert_dict):
    # 1) SAN (DNS), senão 2) CN do subject
    names = [v for k, v in cert_dict.get("subjectAltName", []) if k.lower() == "dns"]
    if not names:
        for tup in cert_dict.get("subject", ()):
            d = dict(tup)
            cn = d.get("commonName")
            if cn:
                names.append(cn)
    return names

def _match_hostname_fallback(host: str, names):
    host = host.lower()
    for pattern in (n.lower() for n in names):
        if pattern.startswith("*."):
            suf = pattern[1:]  
            if host.endswith(suf) and host.count(".") >= suf.count(".")+1:
                return True
        if host == pattern:
            return True
    return False

def _hostname_ok(cert, host):
    try:
        ssl.match_hostname(cert, host)
        return True
    except Exception:
        pass
    names = _extract_dns_names(cert)
    return _match_hostname_fallback(host, names) if names else False

def get_ssl_info(host: str, port=443, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        expiry = _parse_cert_time(cert.get("notAfter")) if cert.get("notAfter") else None
        hn_ok  = _hostname_ok(cert, host)

        issuer  = dict(x[0] for x in cert.get("issuer",  ())).get("organizationName", "")
        subject = dict(x[0] for x in cert.get("subject", ())).get("commonName", "")

        return {
            "ok": True,
            "expiry": expiry.isoformat() if expiry else None,
            "days_to_expiry": None if not expiry else int((expiry - datetime.now(timezone.utc)).days),
            "hostname_match": hn_ok,
            "issuer": issuer,
            "subject": subject,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_ssl(url: str, timeout=8):
    u = urlparse(normalize_url(url))
    host = u.hostname
    if not host:
        return {"ok": False, "error": "invalid host"}
    return get_ssl_info(host, timeout=timeout)

def whois_age_days(domain: str, timeout=10):
    try:
        import whois # python-whois
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, (list, tuple)):
            created = created[0]
        if not created:
            return {"ok": True, "days": None, "note": "creation_date not found"}
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        days = int((datetime.now(timezone.utc) - created).days)
        return {"ok": True, "days": days}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if not a: return len(b)
    if not b: return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost))
        prev = curr
    return prev[-1]

def similar_to_brands(domain: str, brands_list: list) -> dict:
    d = {"best_brand": None, "distance": None, "ratio": None}
    best = None
    for br in brands_list:
        dist = levenshtein(domain, br)
        ratio = dist / max(len(domain), len(br))
        if (best is None) or (ratio < best[2]):
            best = (br, dist, ratio)
    if best:
        d["best_brand"], d["distance"], d["ratio"] = best
    return d

def looks_dynamic_dns(domain: str) -> bool:
    return any(domain.endswith(suf) for suf in DYN_DNS_HOSTS)

def analyze_content(url: str, timeout=8):
    try:
        r = requests.get(normalize_url(url), timeout=timeout, headers={"User-Agent":"phishguard-b/1.0"})
        html = r.text
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        has_password = any(inp.get("type","").lower() == "password" for inp in soup.find_all("input"))
        text = soup.get_text(" ").lower()
        keywords = [k for k in SUSPICIOUS_KEYWORDS_PT if k in text]
        return {"ok": True, "status": r.status_code, "forms": len(forms), "has_password_field": bool(has_password),
                "keywords": keywords[:10]}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def compute_score(features: dict) -> dict:
    score = 0
    reasons = []
    bl = features.get("blacklists", {})
    if bl.get("OpenPhish", {}).get("match_exact"):
        score += 80; reasons.append("Listado no OpenPhish (match exato)")
    elif bl.get("OpenPhish", {}).get("match_host"):
        score += 60; reasons.append("Host presente no OpenPhish")
    if features.get("digits_ratio", 0) > 0.3:
        score += 10; reasons.append("Domínio com muitos dígitos")
    if features.get("subdomains", 0) >= 3:
        score += 10; reasons.append("Excesso de subdomínios")
    if features.get("special_chars", False):
        score += 10; reasons.append("Caracteres especiais na URL")
    age = features.get("whois", {}).get("days")
    if age is not None and age < 60:
        score += 10; reasons.append(f"Domínio muito novo ({age} dias)")
    if features.get("dynamic_dns"):
        score += 10; reasons.append("Uso de DNS dinâmico")
    sslinfo = features.get("ssl", {})
    if sslinfo.get("ok"):
        if sslinfo.get("hostname_match") is False:
            score += 25; reasons.append("Certificado não corresponde ao host")
        dte = sslinfo.get("days_to_expiry")
        if dte is not None and dte <= 0:
            score += 25; reasons.append("Certificado expirado")
    else:
        score += 10; reasons.append("Sem SSL válido ou erro ao obter certificado")
    red = features.get("redirects", {})
    if red.get("ok"):
        if red.get("count", 0) >= 3:
            score += 10; reasons.append("Muitos redirecionamentos")
        if red.get("cross_domain"):
            score += 10; reasons.append("Redirecionamento para outro domínio")
    cont = features.get("content", {})
    trusted = features.get("trusted_brand", False)
    if cont.get("ok"):
        if cont.get("has_password_field") and not trusted:
            score += 10; reasons.append("Página com formulário de login (domínio não reconhecido)")
        if cont.get("keywords") and not trusted:
            score += 10; reasons.append("Palavras sensíveis detectadas (domínio não reconhecido)")

    label = "Seguro"
    if score >= 70: label = "Alto risco"
    elif score >= 40: label = "Risco moderado"
    return {"score": int(min(score,100)), "label": label, "reasons": reasons}

def analyze_url(url: str, brands: list) -> dict:
    url = normalize_url(url)
    domain = get_registered_domain(url)
    trusted = domain in set(brands)
    features = {
        "url": url,
        "domain": domain,
        "subdomains": count_subdomains(url),
        "special_chars": has_special_chars_in_path(url),
        "digits_ratio": digits_ratio_in_domain(url),
        "dynamic_dns": looks_dynamic_dns(domain),
        "trusted_brand": trusted,
    }

    result_op = check_openphish(url)
    features["blacklists"] = {"OpenPhish": result_op}
    features["whois"] = whois_age_days(domain)
    features["ssl"] = check_ssl(url)
    features["redirects"] = check_redirects(url)
    sim = similar_to_brands(domain, brands)
    features["brand_similarity"] = sim
    features["content"] = analyze_content(url)
    features["risk"] = compute_score(features)
    features["timestamp"] = datetime.utcnow().isoformat()+"Z"
    return features
