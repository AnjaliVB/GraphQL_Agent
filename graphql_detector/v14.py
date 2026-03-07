import requests
import json
import sys
import urllib3
import concurrent.futures
import re
import time
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
            # Strict check: Must be valid JSON
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
            
            try:
                with open(filename, "w") as f:
                    json.dump(self.schema, f, indent=4)
                file_saved = True
            except:
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
                        
                        leaked_content = "No specific data fields found (might need schema for specific fields)."
                        
                        if isinstance(data_ex, dict) and data_ex.get('data') and data_ex['data'].get(result_key):
                            real_data = {k:v for k,v in data_ex['data'][result_key].items() if v is not None}
                            if real_data:
                                leaked_content = json.dumps(real_data, indent=2)
                        
                        if not isinstance(data_ex, dict) or 'errors' in data_ex:
                             extraction_query = f'query {{ {target["name"]}({target["arg_name"]}: "{test_id}") {{ id }} }}'
                             data_ex2, _ = self.send_query(extraction_query)
                             if isinstance(data_ex2, dict) and data_ex2.get('data') and data_ex2['data'].get(result_key):
                                 leaked_content = json.dumps(data_ex2['data'][result_key], indent=2)

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
    """
    STRICT CHECK: Eliminates false positives.
    1. Must be valid JSON.
    2. Must have 'data' key OR 'errors' key.
    3. 'errors' must be a LIST (Standard GraphQL), not just {"error": "msg"}.
    """
    try:
        # Optimization: Check content-type header first if possible
        content_type = response.headers.get('Content-Type', '')
        if 'json' not in content_type.lower():
            # Allow if body is json but header is wrong (rare but happens)
            pass 

        data = response.json()
        
        if isinstance(data, dict):
            # Standard GraphQL success response
            if "data" in data:
                return True
            
            # Standard GraphQL error response: {"errors": [ ... ]}
            if "errors" in data:
                # This differentiates GraphQL from generic REST API errors like {"error": "Not Found"}
                if isinstance(data['errors'], list):
                    return True
    except:
        pass
    return False

def validate_endpoint_strict(url):
    """
    Final validation. Only accepts confirmed JSON GraphQL responses.
    Filters out 404s and generic 403s.
    """
    headers = {'Content-Type': 'application/json', 'User-Agent': HEADERS['User-Agent']}
    
    try:
        # Test 1: Valid Query
        r = requests.post(url, json={"query": "{__typename}"}, headers=headers, timeout=10, verify=False)
        
        # Filter 404 Not Found immediately
        if r.status_code == 404:
            return False, "Not Found"

        # Filter generic text/html responses (often custom 404s or login pages)
        content_type = r.headers.get('Content-Type', '')
        if 'html' in content_type.lower():
            return False, "HTML Response (Not API)"

        # Case A: 200 OK with valid JSON GraphQL structure
        if r.status_code == 200 and is_graphql_json(r):
            return True, "Valid GraphQL (200 OK)"

        # Case B: 400/500 Error BUT contains valid GraphQL error JSON
        if r.status_code in [400, 500] and is_graphql_json(r):
            return True, f"Valid (GraphQL Error JSON {r.status_code})"

        # Case C: Auth Required (401, 403, 405)
        # ONLY accept if it looks like an API response. 
        # A 403 HTML page is not a GraphQL endpoint.
        if r.status_code in [401, 403, 405]:
            if 'json' in content_type.lower() or is_graphql_json(r):
                return True, f"Found (Auth Required - {r.status_code})"
            else:
                return False, "Auth Error (Non-JSON)"
             
    except: pass

    # Test 2: Malformed Query (Error Based)
    try:
        r = requests.post(url, json={"query": "{"}, headers=headers, timeout=10, verify=False)
        
        # Filter 404s again
        if r.status_code == 404:
            return False, "Not Found"
            
        # Must return valid JSON error structure
        if is_graphql_json(r):
            return True, "Valid (Error-Based JSON)"
    except: pass

    return False, "Invalid"

def test_endpoint_loose(url):
    """
    Discovery check. Fast but filters out obvious non-GraphQL URLs.
    """
    headers = {'Content-Type': 'application/json', 'User-Agent': HEADERS['User-Agent']}
    try:
        r = requests.post(url, json={"query": "{__typename}"}, headers=headers, timeout=5, verify=False)
        
        # Immediately skip 404s and HTML responses
        if r.status_code == 404: return False
        if 'html' in r.headers.get('Content-Type', '').lower(): return False
        
        # Strict: Only pass if it is valid JSON GraphQL response
        if is_graphql_json(r):
            return True
    except: 
        pass
    return False

def discover_endpoint_bruteforce(base_url):
    print(f"[*] [Discovery] Brute-forcing paths on {base_url}...")
    base_url = base_url.rstrip("/")
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(test_endpoint_loose, f"{base_url}{path}"): path for path in GRAPHQL_PATHS}
        for future in concurrent.futures.as_completed(future_to_url):
            target = f"{base_url}{future_to_url[future]}"
            try:
                if future.result(): found.append(target)
            except: continue
    return found

def crawl_website(start_url, max_depth=1):
    print(f"[*] [Discovery] Crawling {start_url}...")
    visited = set()
    to_visit = [(start_url, 0)]
    found = set()
    session = requests.Session()
    session.headers.update(HEADERS)
    while to_visit:
        current_url, depth = to_visit.pop(0)
        if current_url in visited or depth > max_depth: continue
        visited.add(current_url)
        parsed_current = urlparse(current_url)
        
        # Check the current URL
        if test_endpoint_loose(current_url):
            found.add(current_url)
            continue
        
        try:
            response = session.get(current_url, timeout=10, verify=False, allow_redirects=True)
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type: continue
            
            potential_paths = re.findall(r'[\"\'](.*?(?:graphql|gql|api|query).*?)[\"\']', response.text, re.IGNORECASE)
            for path in potential_paths:
                full_url = urljoin(current_url, path)
                if len(path) > 128 or path.startswith("data:"): continue
                if test_endpoint_loose(full_url): found.add(full_url)
            
            links = re.findall(r'href=[\"\'](.*?)[\"\']', response.text)
            for link in links:
                full_link = urljoin(current_url, link)
                parsed_link = urlparse(full_link)
                if parsed_link.netloc == parsed_current.netloc:
                    if full_link not in visited: to_visit.append((full_link, depth + 1))
        except: pass
    return list(found)

# --- MAIN EXECUTION ---

if __name__ == "__main__":
    print("==========================================")
    print("   GraphQL Auto-Discovery & Vulnerability Scanner")
    print("==========================================")
    
    target_input = input("Enter target URL or domain: ").strip()

    if not target_input: sys.exit("URL cannot be empty.")
    if not target_input.startswith("http"): target_input = "https://" + target_input

    # 1. CHECK INPUT URL FIRST
    print(f"[*] Checking input URL: {target_input}")
    is_valid, status = validate_endpoint_strict(target_input)
    
    valid_targets = []
    
    if is_valid:
        print(f"[+] Input URL is a valid endpoint ({status}). Skipping discovery phase.")
        valid_targets.append(target_input)
    else:
        print(f"[-] Input URL validation failed ({status}). Starting discovery...")
        parsed = urlparse(target_input)
        base_domain = f"{parsed.scheme}://{parsed.netloc}"
        
        potential_targets = set()
        potential_targets.update(crawl_website(target_input, max_depth=1))
        potential_targets.update(discover_endpoint_bruteforce(base_domain))
        
        if potential_targets:
            print(f"\n[*] Validating {len(potential_targets)} potential endpoints found...")
            for url in potential_targets:
                v_is_valid, v_status = validate_endpoint_strict(url)
                if v_is_valid:
                    print(f"    [+] CONFIRMED: {url} ({v_status})")
                    valid_targets.append(url)
                else:
                    # Optional: Uncomment to see what was rejected
                    # print(f"    [-] REJECTED: {url} ({v_status})")
                    pass
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
