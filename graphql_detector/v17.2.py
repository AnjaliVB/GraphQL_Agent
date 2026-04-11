import requests
import json
import sys
import urllib3
import concurrent.futures
import re
import socket
import ipaddress
import os
import threading
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

# Thread-safe set for visited URLs
visited_lock = threading.Lock()

# --- SECURITY HARDENING FUNCTIONS ---

def is_private_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_reserved:
            return True
        if ip_obj in ipaddress.ip_network('169.254.169.254/32'):
            return True
    except ValueError:
        pass
    return False

def resolve_and_validate_url(url, allow_private=False):
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
        print(f"[!] File {filename} already exists. Skipping overwrite.")
        return False
    except Exception as e:
        print(f"[!] Error saving file: {e}")
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
            response = requests.post(self.url, json=payload, headers=self.headers, timeout=5, verify=False)
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
            
            file_saved = secure_save_json(self.schema, filename)

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
                f"Full Schema saved to: {filename}" if file_saved else "Could not save schema to file."
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

    def check_batching(self):
        print("[*] Checking for Query Batching...")
        single_query = {'query': '{ __typename }'}
        batch_payload = [single_query] * 5
        try:
            response = requests.post(self.url, json=batch_payload, headers=self.headers, timeout=5, verify=False)
            if response.status_code == 200 and isinstance(response.json(), list):
                self.findings.append({
                    "vulnerability": "Query Batching Enabled",
                    "severity": "Medium",
                    "description": "The server accepts an array of queries.",
                    "exposed_data": "Potential for DoS via batching."
                })
        except: pass

    def check_sdl_leak(self):
        print("[*] Checking for SDL Leaks...")
        endpoints = [self.url, self.url.replace("/graphql", "/graphql?sdl")]
        for endpoint in endpoints:
            try:
                r = requests.get(endpoint, headers=self.headers, timeout=3, verify=False)
                if r.status_code == 200 and "type " in r.text and "Query" in r.text:
                    if "json" not in r.headers.get('Content-Type', ''):
                        self.findings.append({
                            "vulnerability": "SDL Leak",
                            "severity": "Medium",
                            "description": f"Full schema exposed in plain text at: {endpoint}",
                            "exposed_data": "Schema leaked in plain text."
                        })
                        return
            except: pass

    def check_auto_idor(self):
        print("[*] Running Automated IDOR / Data Exposure Analysis...")
        targets = []
        
        if self.schema and self.schema.get('queryType'):
            for field in self.schema['queryType'].get('fields', []):
                for arg in field['args']:
                    arg_name_lower = arg['name'].lower()
                    type_name = arg.get('type', {}).get('name', '')
                    if 'id' in arg_name_lower or type_name == 'ID':
                        targets.append({"name": field["name"], "arg_name": arg["name"]})
                        break
        else:
            common_guesses = [
                {"name": "user", "arg_name": "id"}, {"name": "getUser", "arg_name": "id"},
                {"name": "node", "arg_name": "id"}, {"name": "post", "arg_name": "id"}
            ]
            targets.extend(common_guesses)

        if not targets: return

        test_ids = ["1", "2", "100"]
        for target in targets:
            for test_id in test_ids:
                check_query = f'query {{ {target["name"]}({target["arg_name"]}: "{test_id}") {{ __typename }} }}'
                data, status = self.send_query(check_query)
                if isinstance(data, dict) and 'errors' not in data and 'data' in data:
                    result_key = list(data['data'].keys())[0]
                    if data['data'][result_key] is not None:
                        self.findings.append({
                            "vulnerability": "Unauthenticated Data Exposure (IDOR)",
                            "severity": "High",
                            "description": f"Query '{target['name']}' returned data for ID '{test_id}'.",
                            "exposed_data": "Accessible without auth."
                        })
                        break 

    def check_version_exposure(self):
        print("[*] Checking for GraphQL Version & Engine Info...")
        version_info = []
        
        # 1. Check HTTP Headers for version disclosure
        try:
            r = requests.post(self.url, json={"query": "{__typename}"}, headers=self.headers, timeout=5, verify=False)
            headers = r.headers
            
            # Common headers that leak version
            interesting_headers = [
                'Server', 'X-Powered-By', 'X-GraphQL-Version', 
                'X-Apollo-Server-Version', 'X-Hasura-Version'
            ]
            
            for h in interesting_headers:
                if headers.get(h):
                    version_info.append(f"HTTP Header '{h}': {headers.get(h)}")
            
            # Fingerprinting based on headers
            if 'x-apollo-tracing' in headers or 'x-apollo-server' in str(headers).lower():
                version_info.append("Detected Engine: Apollo Server (Header Fingerprint)")
            if 'hasura' in str(headers).lower():
                version_info.append("Detected Engine: Hasura (Header Fingerprint)")
                
        except Exception:
            pass

        # 2. Check Schema for engine-specific types (if introspection enabled)
        if self.schema:
            type_names = [t['name'] for t in self.schema['types']]
            
            # Hasura Detection
            if any("hasura" in t.lower() for t in type_names):
                version_info.append("Detected Engine: Hasura GraphQL Engine (Schema Types)")
            
            # Apollo Federation Detection
            if any(t in type_names for t in ['_Service', '_Entity', 'federation']):
                version_info.append("Detected Engine: Apollo Federation (Schema Types)")

            # Graphene (Python) Detection
            if any("graphene" in t.lower() for t in type_names):
                 version_info.append("Detected Engine: Graphene (Python)")

            # AWS AppSync Detection
            if any("appsync" in t.lower() for t in type_names):
                 version_info.append("Detected Engine: AWS AppSync")
            
            # 3. Check for specific root query fields that expose version
            if self.schema.get('queryType') and self.schema['queryType'].get('fields'):
                for f in self.schema['queryType']['fields']:
                    fname_lower = f['name'].lower()
                    # Look for fields named version, info, build, etc.
                    if fname_lower in ['version', 'build', 'info', 'release', 'systemstatus']:
                        # Try to query it
                        q = f'query {{ {f["name"]} }}'
                        d, _ = self.send_query(q)
                        val = "Unknown/Error"
                        if d and 'data' in d and d['data'].get(f['name']):
                            val = d['data'][f['name']]
                            # Format if dict/list
                            if isinstance(val, (dict, list)):
                                val = json.dumps(val)
                        version_info.append(f"Exposed Version Field '{f['name']}': {val}")

        if version_info:
            # Print immediately to console
            print("[+] GraphQL Version/Engine Info Detected:")
            for line in version_info:
                print(f"    - {line}")

            self.findings.append({
                "vulnerability": "GraphQL Version/Engine Exposure",
                "severity": "Low",
                "description": "The server leaks version information via headers or schema.",
                "exposed_data": "\n".join(version_info)
            })

    def run(self):
        print(f"\n=== Scanning {self.url} ===")
        self.check_introspection()
        self.check_version_exposure() # Run after introspection to use schema data
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
                
                # FIX: RESTORED PRINTING OF EXPOSED DATA
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
    is_safe, msg = resolve_and_validate_url(url, allow_private=allow_private)
    if not is_safe: return False, msg

    headers = {'Content-Type': 'application/json', 'User-Agent': HEADERS['User-Agent']}
    try:
        r = requests.post(url, json={"query": "{__typename}"}, headers=headers, timeout=3, verify=False)
        if r.status_code == 404: return False, "Not Found"
        if 'html' in r.headers.get('Content-Type', '').lower(): return False, "HTML Response"
        if r.status_code == 200 and is_graphql_json(r): return True, "Valid GraphQL"
        if r.status_code in [400, 500] and is_graphql_json(r): return True, "Valid (Error JSON)"
        if r.status_code in [401, 403, 405] and 'json' in r.headers.get('Content-Type', '').lower():
             return True, f"Found (Auth Required - {r.status_code})"
    except: pass
    return False, "Invalid"

def test_endpoint_loose(url, allow_private=False):
    is_safe, _ = resolve_and_validate_url(url, allow_private=allow_private)
    if not is_safe: return False
    headers = {'Content-Type': 'application/json', 'User-Agent': HEADERS['User-Agent']}
    try:
        r = requests.post(url, json={"query": "{__typename}"}, headers=headers, timeout=3, verify=False)
        if r.status_code == 404: return False
        if 'html' in r.headers.get('Content-Type', '').lower(): return False
        if is_graphql_json(r): return True
    except: pass
    return False

def discover_endpoint_bruteforce(base_url, allow_private=False):
    print(f"[*] [Discovery] Brute-forcing paths on {base_url} (Fast Mode)...")
    base_url = base_url.rstrip("/")
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(test_endpoint_loose, f"{base_url}{path}", allow_private): path for path in GRAPHQL_PATHS}
        for future in concurrent.futures.as_completed(future_to_url):
            target = f"{base_url}{future_to_url[future]}"
            try:
                if future.result(): found.append(target)
            except: continue
    return found

def extract_endpoints_from_text(text, base_url):
    found_urls = set()
    regex = r'["\']([^"\']*(?:graphql|api|query|gql|endpoint)[^"\']*)["\']'
    matches = re.findall(regex, text, re.IGNORECASE)
    for match in matches:
        if len(match) > 128 or match.startswith("data:"): continue
        full_url = urljoin(base_url, match)
        found_urls.add(full_url)
    return list(found_urls)

def crawl_website(start_url, allow_private=False):
    print(f"[*] [Discovery] Crawling {start_url} (Parallel Mode)...")
    
    session = requests.Session()
    session.headers.update(HEADERS)
    visited = set()
    to_fetch = {start_url}
    found_endpoints = set()
    futures = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Submit initial URL
        futures[executor.submit(session.get, start_url, timeout=3, verify=False, allow_redirects=True)] = start_url
        
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            try:
                response = future.result()
                visited.add(url)
                content_type = response.headers.get('Content-Type', '').lower()
                
                if 'json' in content_type:
                     if test_endpoint_loose(url, allow_private): found_endpoints.add(url)
                
                if 'text/html' in content_type:
                    js_files = re.findall(r'src=[\"\'](.*?\.js.*?)[\"\']', response.text, re.IGNORECASE)
                    html_endpoints = extract_endpoints_from_text(response.text, url)
                    
                    for ep in html_endpoints:
                        if test_endpoint_loose(ep, allow_private): found_endpoints.add(ep)
                    
                    for js_path in js_files:
                        full_url = urljoin(url, js_path)
                        if full_url not in visited:
                             try:
                                 js_resp = session.get(full_url, timeout=3, verify=False)
                                 js_endpoints = extract_endpoints_from_text(js_resp.text, full_url)
                                 for ep in js_endpoints:
                                     if test_endpoint_loose(ep, allow_private): found_endpoints.add(ep)
                             except:
                                 pass
            except:
                pass

    return list(found_endpoints)

# --- MAIN EXECUTION ---

if __name__ == "__main__":
    print("==========================================")
    print("   GraphQL Scanner (Optimized & Hardened)")
    print("==========================================")
    
    target_input = input("Enter target URL or domain: ").strip()

    if not target_input: sys.exit("URL cannot be empty.")
    if not target_input.startswith("http"): target_input = "https://" + target_input

    parsed_initial = urlparse(target_input)
    try:
        initial_ip = socket.gethostbyname(parsed_initial.netloc.split(':')[0])
        user_input_is_private = is_private_ip(initial_ip)
    except:
        user_input_is_private = False

    print(f"[*] Checking input URL: {target_input}")
    is_valid, status = validate_endpoint_strict(target_input, allow_private=user_input_is_private)
    
    valid_targets = []
    
    if is_valid:
        print(f"[+] Input URL is a valid endpoint ({status}). Skipping discovery phase.")
        valid_targets.append(target_input)
    else:
        print(f"[-] Input URL validation failed ({status}). Starting fast discovery...")
        base_domain = f"{parsed_initial.scheme}://{parsed_initial.netloc}"
        
        potential_targets = set()
        potential_targets.update(crawl_website(target_input, allow_private=user_input_is_private))
        potential_targets.update(discover_endpoint_bruteforce(base_domain, allow_private=user_input_is_private))
        
        if potential_targets:
            print(f"\n[*] Validating {len(potential_targets)} potential endpoints...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_url = {executor.submit(validate_endpoint_strict, url, user_input_is_private): url for url in potential_targets}
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        v_is_valid, v_status = future.result()
                        if v_is_valid:
                            print(f"    [+] CONFIRMED: {url} ({v_status})")
                            valid_targets.append(url)
                    except: pass
        else:
            print("\n[!] Discovery found 0 potential endpoints.")

    if not valid_targets:
        print("\n" + "="*40)
        print(" RESULT: No GraphQL endpoints found on this target.")
        print("="*40)
    else:
        print(f"\n[*] Starting vulnerability scan on {len(valid_targets)} verified endpoint(s)...")
        for target in valid_targets:
            scanner = GraphQLScanner(target)
            scanner.run()
