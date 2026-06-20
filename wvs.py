import argparse
import requests
import sys
import urllib.parse
import urllib3
import time
import re
import subprocess
import os
import socket

OUTPUT_FILE = ""

DEFAULT_CREDS = [
    ("root", "root"), ("root", "password"), ("root", "admin"), ("root", ""),
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("test", "test"), ("user", "user"), ("ftp", "ftp"),
    ("postgres", "postgres"), ("ubuntu", "ubuntu")
]

def log_finding(message):
    print(message)
    if OUTPUT_FILE:
        with open(OUTPUT_FILE, "a") as f:
            f.write(message + "\n")

def get_subdomains(domain):
    subdomains = set()
    try:
        result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True, timeout=120)
        for line in result.stdout.splitlines():
            clean = line.strip()
            if clean:
                subdomains.add(clean)
    except Exception:
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = requests.get(url, timeout=15)
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                for sub in name_value.split('\n'):
                    clean_sub = sub.strip().lower().replace('*.', '')
                    if clean_sub and clean_sub.endswith(domain):
                        subdomains.add(clean_sub)
        except Exception:
            pass
    return list(subdomains)

def crawl_for_params(url):
    urls_with_params = set()
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        resp = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
        links = re.findall(r'href=[\'"]?([^\'" >]+)', resp.text)
        for link in links:
            if not link.startswith('http'):
                link = urllib.parse.urljoin(url, link)
            parsed = urllib.parse.urlparse(link)
            if parsed.query and parsed.netloc == urllib.parse.urlparse(url).netloc:
                urls_with_params.add(link)
    except Exception:
        pass
    return list(urls_with_params)

def check_exposed_files(base_url):
    exposed_paths = [
        '/.env', '/.git/HEAD', '/.git/config', '/wp-config.php', '/phpinfo.php', 
        '/.DS_Store', '/robots.txt', '/sitemap.xml', '/backup.zip', '/www.zip', 
        '/db.sql', '/database.sql', '/config.php', '/.htaccess', '/.htpasswd',
        '/admin/', '/phpmyadmin/', '/wp-admin/', '/.aws/credentials', '/server-status'
    ]
    found = False
    for path in exposed_paths:
        try:
            test_url = base_url.rstrip('/') + path
            resp = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
            if resp.status_code == 200:
                if path in ['/.git/HEAD', '/.env', '/wp-config.php', '/.aws/credentials']:
                    log_finding(f"[+] EXPOSED_SENSITIVE_FILE | {test_url}")
                else:
                    log_finding(f"[+] EXPOSED_FILE | {test_url}")
                found = True
        except Exception:
            pass
    if not found:
        log_finding(f"[-] no exposed files found on {base_url}")

def check_security_headers(base_url):
    try:
        resp = requests.get(base_url, timeout=5, verify=False)
        headers = resp.headers
        missing = []
        if 'X-Frame-Options' not in headers: missing.append('X-Frame-Options')
        if 'X-Content-Type-Options' not in headers: missing.append('X-Content-Type-Options')
        if 'Strict-Transport-Security' not in headers: missing.append('HSTS')
        if 'Content-Security-Policy' not in headers: missing.append('CSP')
        if 'X-XSS-Protection' not in headers: missing.append('X-XSS-Protection')
        
        if len(missing) >= 3:
            log_finding(f"[+] MISSING_SECURITY_HEADERS | {base_url} | Missing: {', '.join(missing)}")
        else:
            log_finding(f"[-] security headers are mostly configured on {base_url}")
    except Exception:
        pass

def run_nmap_and_test_services(target_ip):
    log_finding(f"[*] running port scan on {target_ip}...")
    open_ports = []
    try:
        result = subprocess.run(['nmap', '-p-', '-sV', '--open', target_ip], capture_output=True, text=True, timeout=300)
        for line in result.stdout.splitlines():
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                port = parts[0].split('/')[0]
                service = parts[2] if len(parts) > 2 else 'unknown'
                open_ports.append((port, service))
                log_finding(f"[+] open port found | {target_ip}:{port} ({service})")
        
        if not open_ports:
            log_finding(f"[-] no open ports found on {target_ip}")
            return

        log_finding("[*] testing default credentials on open services...")
        for port, service in open_ports:
            if service in ['mysql', 'mariadb']:
                test_mysql_auth(target_ip, int(port))
            elif service in ['ssh', 'openssh']:
                test_ssh_auth(target_ip, int(port))
            elif service in ['ftp', 'vsftpd', 'proftpd']:
                test_ftp_auth(target_ip, int(port))
                
    except Exception as e:
        log_finding(f"[-] port scan failed or not installed: {e}")

def test_mysql_auth(host, port):
    for user, password in DEFAULT_CREDS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(1024)
            if b'mysql' in banner.lower() or b'mariadb' in banner.lower():
                log_finding(f"[+] potential mysql/mariadb default creds | {host}:{port} | {user}:{password}")
            sock.close()
            break 
        except Exception:
            pass

def test_ssh_auth(host, port):
    for user, password in DEFAULT_CREDS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(1024)
            if b'ssh' in banner.lower():
                log_finding(f"[+] potential ssh default creds | {host}:{port} | {user}:{password}")
            sock.close()
            break
        except Exception:
            pass

def test_ftp_auth(host, port):
    for user, password in DEFAULT_CREDS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(1024)
            if b'ftp' in banner.lower():
                log_finding(f"[+] potential ftp default creds | {host}:{port} | {user}:{password}")
            sock.close()
            break
        except Exception:
            pass

def test_sqli_error_based(url, param, value):
    payloads = ["'", "''", "')", "'))", "' OR '1'='1", "' OR '1'='1' --", "1' AND 1=1 --", "1' AND 1=2 --"]
    error_patterns = [
        r"SQL syntax.*MySQL", r"MySQL.*fetch", r"valid MySQL result", r"check the manual that",
        r"Unknown column", r"where clause", r"Unclosed quotation mark", r"SQL query failed",
        r"Database error", r"ORA-[0-9]", r"Oracle error", r"PostgreSQL.*ERROR", r"PG::SyntaxError",
        r"Microsoft Access.*Database", r"Incorrect syntax near", r"Warning.*mysql_",
        r"Microsoft SQL Server.*Error", r"ODBC SQL Server Driver", r"quoted string not properly terminated"
    ]
    for payload in payloads:
        try:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            query[param] = [value + payload]
            new_query = urllib.parse.urlencode(query, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            response = requests.get(test_url, timeout=10, verify=False)
            body = response.text
            for pattern in error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return True, payload
            if response.status_code == 500:
                return True, payload
        except Exception:
            pass
    return False, None

def test_nosql_injection(url, param, value):
    payloads = ['{"$gt": ""}', '{"$ne": null}', '1[$ne]=1']
    for payload in payloads:
        try:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            query[param] = [value + payload]
            new_query = urllib.parse.urlencode(query, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            response = requests.get(test_url, timeout=10, verify=False)
            if response.status_code == 200 and len(response.text) > 0:
                if 'error' in response.text.lower() or 'cast' in response.text.lower() or 'mongodb' in response.text.lower():
                    return True, payload
        except Exception:
            pass
    return False, None

def test_sqli_boolean_based(url, param, value):
    try:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        query[param] = [value + "' AND '1'='1"]
        true_query = urllib.parse.urlencode(query, doseq=True)
        true_url = parsed._replace(query=true_query).geturl()
        query[param] = [value + "' AND '1'='2"]
        false_query = urllib.parse.urlencode(query, doseq=True)
        false_url = parsed._replace(query=false_query).geturl()
        resp_true = requests.get(true_url, timeout=10, verify=False)
        resp_false = requests.get(false_url, timeout=10, verify=False)
        if len(resp_true.text) != len(resp_false.text):
            return True, "' AND '1'='1"
    except Exception:
        pass
    return False, None

def test_sqli_time_based(url, param, value):
    payloads = ["' AND SLEEP(5)--", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"]
    for payload in payloads:
        try:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            query[param] = [value + payload]
            new_query = urllib.parse.urlencode(query, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            start_time = time.time()
            requests.get(test_url, timeout=15, verify=False)
            elapsed = time.time() - start_time
            if elapsed >= 4:
                return True, payload
        except Exception:
            pass
    return False, None

def test_xss(url, param, value):
    payload = "<script>alert(1)</script>"
    try:
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        query[param] = [value + payload]
        new_query = urllib.parse.urlencode(query, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        response = requests.get(test_url, timeout=10, verify=False)
        if payload in response.text:
            return True, payload
    except Exception:
        pass
    return False, None

def scan_url(url, is_api):
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        requests.get(url, timeout=5, verify=False)
    except Exception:
        log_finding(f"[-] target unreachable | {url}")
        return

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    
    if is_api:
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        log_finding(f"[*] scanning api endpoints for {base_url}")
        api_paths = ['/api/', '/v1/', '/graphql', '/rest/', '/swagger.json', '/openapi.json', '/api/v1/']
        for path in api_paths:
            try:
                api_url = base_url.rstrip('/') + path
                response = requests.get(api_url, timeout=5, verify=False)
                if response.status_code in [200, 400, 401, 403, 500]:
                    log_finding(f"[+] API_ENDPOINT | {api_url}")
            except Exception:
                pass

    if params:
        found_vuln = False
        for param in params:
            original_value = params[param][0]
            
            is_vuln, payload = test_sqli_error_based(url, param, original_value)
            if is_vuln:
                log_finding(f"[+] SQLi (Error) | {url} | {param} | payload: {payload}")
                found_vuln = True
                continue
                
            is_vuln, payload = test_nosql_injection(url, param, original_value)
            if is_vuln:
                log_finding(f"[+] NoSQLi | {url} | {param} | payload: {payload}")
                found_vuln = True
                continue

            is_vuln, payload = test_sqli_boolean_based(url, param, original_value)
            if is_vuln:
                log_finding(f"[+] SQLi (Boolean) | {url} | {param} | payload: {payload}")
                found_vuln = True
                continue
                
            is_vuln, payload = test_sqli_time_based(url, param, original_value)
            if is_vuln:
                log_finding(f"[+] SQLi (Time) | {url} | {param} | payload: {payload}")
                found_vuln = True
                continue
                
            is_vuln, payload = test_xss(url, param, original_value)
            if is_vuln:
                log_finding(f"[+] XSS | {url} | {param} | payload: {payload}")
                found_vuln = True
                
        if not found_vuln:
            log_finding(f"[-] no injection vulns found on {url}")

def main():
    global OUTPUT_FILE
    parser = argparse.ArgumentParser()
    parser.add_argument('file', nargs='?', help='File path')
    parser.add_argument('-d', '--domain', help='Domain')
    parser.add_argument('-ip', '--ip', help='IP')
    parser.add_argument('-api', '--api', action='store_true', help='API mode')
    args = parser.parse_args()

    targets = []
    if args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            OUTPUT_FILE = "wss_results.txt"
        except Exception:
            print("[-] File not found")
            sys.exit(1)
    elif args.domain:
        print(f"[*] enumerating subdomains for {args.domain}...")
        targets = get_subdomains(args.domain)
        if not targets:
            targets = [args.domain]
        OUTPUT_FILE = f"{args.domain}+.txt"
    elif args.ip:
        targets = [args.ip]
        OUTPUT_FILE = f"{args.ip}+.txt"
    else:
        print("[-] Usage: python3 wss.py <domains.txt> | -d <domain> | -ip <ip> [-api]")
        sys.exit(1)

    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)

    total_subdomains = len(targets)
    log_finding(f"[*] total subdomains discovered: {total_subdomains}")
    
    urls_to_test = []
    for i, target in enumerate(targets):
        log_finding(f"[*] crawling progress: {i+1}/{total_subdomains} - {target}")
        if not target.startswith('http'):
            target = 'http://' + target
        
        log_finding(f"[*] checking surface vulns for {target}")
        check_exposed_files(target)
        check_security_headers(target)
        
        found_urls = crawl_for_params(target)
        urls_to_test.extend(found_urls)

    urls_to_test = list(set(urls_to_test))
    total_urls = len(urls_to_test)
    log_finding(f"[*] total parameterized URLs found: {total_urls}")
    log_finding("[*] starting deep vulnerability scan...")

    for i, url in enumerate(urls_to_test):
        log_finding(f"[*] scanning progress: {i+1}/{total_urls} - {url}")
        scan_url(url, args.api)

    if args.ip:
        log_finding("[*] starting server port and service scan...")
        run_nmap_and_test_services(args.ip)
    elif args.domain:
        log_finding("[*] starting server port and service scan on main domain...")
        run_nmap_and_test_services(args.domain)
        
    log_finding(f"[*] scan complete. results saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
