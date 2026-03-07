import requests
import json
import sys
import urllib3
import concurrent.futures
import re
import socket
import ipaddress
import os
from urllib.parse import urlparse, urljoin
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global headers
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': '*/*'
}

# Unique list of common paths
GRAPHQL_PATHS = list(set([
    "/graphql", "/graphql/", "/api/graphql", "/api/graphql/", "/v1/graphql", "/v2/graphql", 
    "/v3/graphql", "/query", "/gql", "/gql/", "/api", "/api/v1", "/api/v2", "/graphql.php", 
    "/graphql-console", "/graphiql", "/playground", "/altair", "/explorer", "/services/graphql", 
    "/graphql/schema", "/console", "/debug/graphql", "/api/public", "/api/internal", 
    "/rest/graphql", "/_graphql", "/api/data", "/api/query/graphql"
]))

# --- SECURITY HARDENING FUNCTIONS ---

def is_private_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_reserved:
            return True
        if ip_obj in ipaddress.ip_network('169.254.169.254/32'): # AWS Metadata
            return True
    except ValueError:
        pass
    return False

def resolve_and_validate_url(url, allow_private=False):
    """
    Security Gate.
    allow_private=True: Used for the INITIAL target (allows localhost/internal).
    allow_private=False: Used for discovered links (blocks internal SSRF).
    """
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False, "Invalid URL structure."
        
        if parsed.scheme not in ['http', 'https']:
            return False, "Invalid scheme."

        hostname = parsed.netloc.split(':')[0]
        
        try:
            ip_str = socket.gethostbyname(hostname)
        except socket.gaierror:
            return False, "Could not resolve hostname."
            
        # SSRF Check logic
        if not allow_private:
            if is_private_ip(ip_str):
                return False, f"Blocked: Target IP {ip_str} is private/internal (SSRF Protection)."
            
        return True, f"Valid target: {ip_str}"
        
    except Exception as e:
        return False, f"URL Validation Error: {str(e)}"

def secure_save_json(data, filename):
    try:
        flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
        with os.fdopen(os.open(filename, flags, 0o600), 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except FileExistsError:
        return False
    except Exception as e:
        print(f"[!] Error saving file securely: {e}")
        return False

# --- SCANNER CLASS ---

class GraphQLScanner:
    def __init__(self, url):
        self.url = url
        self.headers = {'Content-Type': 'application/json', 'User-Agent': HEADERS['User-Agent']}
        self.findings = []
        self.schema = None

    def send_query(self, query, variables=None):
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        try:
            response = requests.post(self.url, json=payload, headers=self.headers, timeout=10, verify=False)
            return response.json(), response.status_code
        except Exception:
            return None, None

    def check_introspection(self):
        print("[*] Checking for Introspection...")
        query = """
        query IntrospectionQuery {
          __schema {
            queryType { name fields { name args { name type { name kind ofType { name kind } } } } }
            mutationType { name fields { name args { name type { name kind ofType { name kind } } } } }
            types { name kind fields { name args { name type { name kind } } type { name kind } } }
          }
        }
        """
        data, status = self.send_query(query)
        
        if isinstance(data, dict) and data.get('data') and data['data'].get('__schema'):
            self.schema = data['data']['__schema']
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            domain = urlparse(self.url).netloc.replace(":", "_")
            filename = f"schema_{domain}_{timestamp}.json"
            
            if secure_save_json(self.schema, filename):
                file_saved = True
            else:
                file_saved = False

            types = self.schema['types']
            exposed_types = [t['name'] for t in types if not t['name'].startswith('__')]
            
            queries = []
            mutations = []
            
            if self.schema.get('queryType') and self.schema['queryType'].get('fields'):
                queries = [f['name'] for f in self.schema['queryType']['fields']]
            
            if self.schema.get('mutationType') and self.schema['mutationType'].get('fields'):
                mutations = [f['name'] for f in self.schema['mutationType']['fields']]

            report_lines = [
                f"Found {len(exposed_types)} types.",
                f"Queries ({len(queries)}): {', '.join(queries[:10])}...",
                f"Mutations ({len(mutations)}): {', '.join(mutations[:10])}...",
                f"Full Schema saved to: {filename}" if file_saved else "Could not save schema securely."
            ]

            self.findings.append({
                "vulnerability": "Introspection Enabled",
                "severity": "Medium",
                "description": "The API exposes its entire schema structure.",
                "exposed_data": "\n".join(report_lines)
            })
        else:
            print("[-] Introspection disabled.")

    def check_field_suggestion(self):
        print("[*] Checking for Field Suggestions...")
        query = '{ __typename usernme }'
        data, status = self.send_query(query)
        if isinstance(data, dict) and 'errors' in data:
            errors = str(data['errors'])
            if "Did you mean" in errors or "did you mean" in errors:
                self.findings.append({
                    "vulnerability": "Field Suggestion Enabled",
                    "severity": "Low",
                    "description": "The API reveals field names via error suggestions.",
                    "exposed_data": f"Server response: {errors[:150]}"
                })
            else:
                print("[-] Field suggestions disabled.")

    def check_batching(self):
        print("[*] Checking for Query Batching...")
        single_query = {'query': '{ __typename }'}
        batch_payload = [single_query] * 5
        try:
            response = requests.post(self.url, json=batch_payload, headers=self.headers, timeout=10, verify=False)
            if response.status_code == 200 and isinstance(response.json(), list):
                self.findings.append({
                    "vulnerability": "Query Batching Enabled",
                    "severity": "Medium",
                    "description": "The server accepts an array of queries.",
                    "exposed_data": "Potential for DoS via batching."
                })
            else:
                print("[-] Query batching disabled.")
        except:
            print("[-] Could not test batching.")

    def check_sdl_leak(self):
        print("[*] Checking for SDL Leaks...")
        endpoints = [self.url, self.url.replace("/graphql", "/graphql?sdl")]
        for endpoint in endpoints:
            try:
                r = requests.get(endpoint, headers=self.headers, timeout=5, verify=False)
                if r.status_code == 200 and "type " in r.text and "Query" in r.text:
                    if "json" not in r.headers.get('Content-Type', ''):
                        self.findings.append({
                            "vulnerability": "SDL Leak",
                            "severity": "Medium",
                            "description": f"Full schema exposed in plain text at: {endpoint}",
                            "exposed_data": "Schema leaked in plain text."
                        })
                        return
            except:
                pass
        print("[-] No SDL leak found.")

    def check_auto_idor(self):
        print("[*] Running Automated IDOR / Data Exposure Analysis...")
        
        targets = []
        
        if self.schema and self.schema.get('queryType'):
            print("[*] Using Schema to find ID-based queries...")
            for field in self.schema['queryType'].get('fields', []):
                for arg in field['args']:
                    arg_name_lower = arg['name'].lower()
                    type_name = arg.get('type', {}).get('name', '')
                    if 'id' in arg_name_lower or type_name == 'ID':
                        targets.append({
                            "name": field["name"],
                            "arg_name": arg["name"],
                            "type": "schema_defined"
                        })
                        break
        else:
            print("[-] Introspection disabled. Guessing common query patterns...")
            common_guesses = [
                {"name": "user", "arg_name": "id"},
                {"name": "getUser", "arg_name": "id"},
                {"name": "node", "arg_name": "id"},
                {"name": "post", "arg_name": "id"},
                {"name": "order", "arg_name": "id"}
            ]
            targets.extend(common_guesses)

        if not targets:
            print("[-] No ID-based queries found.")
            return

        print(f"[*] Testing {len(targets)} query types with common IDs...")

        test_ids = ["1", "2", "100", "admin"]

        for target in targets:
            for test_id in test_ids:
                check_query = f'query {{ {target["name"]}({target["arg_name"]}: "{test_id}") {{ __typename }} }}'
                data, status = self.send_query(check_query)

                if isinstance(data, dict) and 'errors' not in data and 'data' in data:
                    result_key = list(data['data'].keys())[0]
                    if data['data'][result_key] is not None:
                        
                        print(f"    [!] HIT: {target['name']}({target['arg_name']}: {test_id}) is accessible. Extracting data...")
                        
                        safe_fields = ['id', 'email', 'username', 'name', 'role', 'title', 'body', 'description', 'password', 'token']
                        extraction_query = f'query {{ {target["name"]}({target["arg_name"]}: "{test_id}") {{ {" ".join(safe_fields)} }} }}'
                        
                        data_ex, status_ex = self.send_query(extraction_query)
                        
                        leaked_content = "No specific data fields found."
                        
                        if isinstance(data_ex, dict) and data_ex.get('data') and data_ex['data'].get(result_key):
                            real_data = {k:v for k,v in data_ex['data'][result_key].items() if v is not None}
                            if real_data:
                                leaked_content = json.dumps(real_data, indent=2)

                        self.findings.append({
                            "vulnerability": "Unauthenticated Data Exposure (IDOR)",
                            "severity": "High",
                            "description": f"Query '{target['name']}' returned data for ID '{test_id}' without authentication.",
                            "exposed_data": leaked_content
                        })
                        break 

    def run(self):
        print(f"\n=== Scanning {self.url} ===")
        
        self.check_introspection()
        self.check_field_suggestion()
        self.check_batching()
        self.check_sdl_leak()
        self.check_auto_idor()
        
        print("\n--- VULNERABILITY REPORT ---")
        if not self.findings:
            print("No high-confidence vulnerabilities found.")
        else:
            for i, finding in enumerate(self.findings, 1):
                print(f"\n[{i}] {finding['vulnerability']} (Severity: {finding['severity']})")
                print(f"    Description: {finding['description']}")
                if 'exposed_data' in finding:
                    print(f"    [!] EXPOSED DATA:")
                    for line in finding['exposed_data'].split('\n'):
                        print(f"        {line}")
        print("")


# --- VALIDATION & DISCOVERY FUNCTIONS ---

def is_graphql_json(response):
    try:
        data = response.json()
        if isinstance(data, dict):
            if "data" in data: return True
            if "errors" in data and isinstance(data['errors'], list): return True
    except: pass
    return False

def validate_endpoint_strict(url, allow_private=False):
    """
    Validation logic.
    allow_private: passed from main to allow local scanning if user requested it.
    """
    is_safe, msg = resolve_and_validate_url(url, allow_private=allow_private)
    if not is_safe:
        return False, msg

    headers = {'Content-Type': 'application/json', 'User-Agent': HEADERS['User-Agent']}
    
    try:
        r = requests.post(url, json={"query": "{__typename}"}, headers=headers, timeout=10, verify=False)
        
        if r.status_code == 404: return False, "Not Found"
        if 'html' in r.headers.get('Content-Type', '').lower(): return False, "HTML Response"

        if r.status_code == 200 and is_graphql_json(r): return True, "Valid GraphQL (200 OK)"
        if r.status_code in [400, 500] and is_graphql_json(r): return True, f"Valid (GraphQL Error JSON {r.status_code})"
        if r.status_code in [401, 403, 405] and 'json' in r.headers.get('Content-Type', '').lower():
             return True, f"Found (Auth Required - {r.status_code})"
             
    except: pass

    try:
        r = requests.post(url, json={"query": "{"}, headers=headers, timeout=10, verify=False)
        if r.status_code == 404: return False, "Not Found"
        if is_graphql_json(r): return True, "Valid (Error-Based JSON)"
    except: pass

    return False, "Invalid"

def test_endpoint_loose(url, allow_private=False):
    is_safe, _ = resolve_and_validate_url(url, allow_private=allow_private)
    if not is_safe: return False

    headers = {'Content-Type': 'application/json', 'User-Agent': HEADERS['User-Agent']}
    try:
        r = requests.post(url, json={"query": "{__typename}"}, headers=headers, timeout=5, verify=False)
        if r.status_code == 404: return False
        if 'html' in r.headers.get('Content-Type', '').lower(): return False
        if is_graphql_json(r): return True
    except: pass
    return False

def discover_endpoint_bruteforce(base_url, allow_private=False):
    print(f"[*] [Discovery] Brute-forcing paths on {base_url}...")
    base_url = base_url.rstrip("/")
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(test_endpoint_loose, f"{base_url}{path}", allow_private): path for path in GRAPHQL_PATHS}
        for future in concurrent.futures.as_completed(future_to_url):
            target = f"{base_url}{future_to_url[future]}"
            try:
                if future.result(): found.append(target)
            except: continue
    return found

def extract_endpoints_from_text(text, base_url):
    """
    Regex to find potential endpoints in HTML/JS content.
    Looks for strings with keywords graphql, api, query.
    """
    found_urls = set()
    # Look for strings like "graphql", "/api/v1", etc.
    # Regex captures strings in quotes that contain keywords
    regex = r'["\']([^"\']*(?:graphql|api|query|gql|endpoint)[^"\']*)["\']'
    matches = re.findall(regex, text, re.IGNORECASE)
    
    for match in matches:
        # Filter out data URIs or overly long strings
        if len(match) > 128 or match.startswith("data:"):
            continue
        
        full_url = urljoin(base_url, match)
        found_urls.add(full_url)
        
    return list(found_urls)

def crawl_website(start_url, allow_private=False):
    print(f"[*] [Discovery] Crawling {start_url} (JS & HTML)...")
    visited = set()
    to_visit = [(start_url, 0)]
    found = set()
    session = requests.Session()
    session.headers.update(HEADERS)
    
    while to_visit:
        current_url, depth = to_visit.pop(0)
        if current_url in visited or depth > 1: continue # Depth 1 = page + its JS files
        visited.add(current_url)
        
        # Security Check for crawler discovered links
        safe, _ = resolve_and_validate_url(current_url, allow_private=allow_private)
        if not safe: continue

        try:
            response = session.get(current_url, timeout=10, verify=False, allow_redirects=True)
            content_type = response.headers.get('Content-Type', '').lower()
            
            # 1. Check if current URL is an endpoint
            # We treat JSON responses as potential endpoints immediately
            if 'json' in content_type:
                if test_endpoint_loose(current_url, allow_private):
                    found.add(current_url)
                    continue

            # 2. Parse Content
            text_content = response.text
            
            # Check for endpoints in the current file (HTML or JS)
            potentials = extract_endpoints_from_text(text_content, current_url)
            for p_url in potentials:
                if test_endpoint_loose(p_url, allow_private):
                    found.add(p_url)

            # 3. If HTML, find JS files and Links
            if 'text/html' in content_type:
                # Find script sources
                js_files = re.findall(r'src=[\"\'](.*?\.js.*?)[\"\']', text_content, re.IGNORECASE)
                # Add standard links
                links = re.findall(r'href=[\"\'](.*?)[\"\']', text_content, re.IGNORECASE)
                
                all_resources = js_files + links
                
                for res in all_resources:
                    full_url = urljoin(current_url, res)
                    if full_url not in visited:
                        to_visit.append((full_url, depth + 1))
                        
        except Exception as e:
            pass
            
    return list(found)

# --- MAIN EXECUTION ---

if __name__ == "__main__":
    print("==========================================")
    print("   GraphQL Scanner (Security Hardened)")
    print("==========================================")
    
    target_input = input("Enter target URL or domain: ").strip()

    if not target_input: sys.exit("URL cannot be empty.")
    if not target_input.startswith("http"): target_input = "https://" + target_input

    # CHECK IF USER INPUT IS LOCAL/PRIVATE
    # We allow private IPs only if the user explicitly typed it.
    parsed_initial = urlparse(target_input)
    try:
        initial_ip = socket.gethostbyname(parsed_initial.netloc.split(':')[0])
        user_input_is_private = is_private_ip(initial_ip)
    except:
        user_input_is_private = False

    # 1. CHECK INPUT URL FIRST
    print(f"[*] Checking input URL: {target_input}")
    # allow_private = user_input_is_private (True if user typed localhost)
    is_valid, status = validate_endpoint_strict(target_input, allow_private=user_input_is_private)
    
    valid_targets = []
    
    if is_valid:
        print(f"[+] Input URL is a valid endpoint ({status}). Skipping discovery phase.")
        valid_targets.append(target_input)
    else:
        print(f"[-] Input URL is not a direct GraphQL endpoint ({status}). Starting discovery...")
        base_domain = f"{parsed_initial.scheme}://{parsed_initial.netloc}"
        
        potential_targets = set()
        # Pass allow_private flag to discovery functions
        potential_targets.update(crawl_website(target_input, allow_private=user_input_is_private))
        potential_targets.update(discover_endpoint_bruteforce(base_domain, allow_private=user_input_is_private))
        
        if potential_targets:
            print(f"\n[*] Validating {len(potential_targets)} potential endpoints found...")
            for url in potential_targets:
                # Validate discovered endpoints (allow_private logic applied inside)
                v_is_valid, v_status = validate_endpoint_strict(url, allow_private=user_input_is_private)
                if v_is_valid:
                    print(f"    [+] CONFIRMED: {url} ({v_status})")
                    valid_targets.append(url)
        else:
            print("\n[!] Discovery found 0 potential endpoints.")

    # 2. RUN SCANS
    if not valid_targets:
        print("\n" + "="*40)
        print(" RESULT: No GraphQL endpoints found on this target.")
        print("="*40)
    else:
        print(f"\n[*] Starting vulnerability scan on {len(valid_targets)} verified endpoint(s)...")
        for target in valid_targets:
            scanner = GraphQLScanner(target)
            scanner.run()
