import requests
import json
import sys
import urllib3
import concurrent.futures
import re
import time
from urllib.parse import urlparse, urljoin

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global headers
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
}

# Expanded list of common paths
GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/api/graphql", "/api/graphql/", "/v1/graphql", "/v2/graphql", 
    "/v3/graphql", "/query", "/gql", "/gql/", "/api", "/api/v1", "/api/v2", "/graphql.php", 
    "/graphql-console", "/graphiql", "/playground", "/altair", "/explorer", "/services/graphql", 
    "/graphql/schema", "/console", "/debug/graphql", "/api/public", "/api/internal", 
    "/rest/graphql", "/_graphql", "/api/data", "/api/query/graphql", "/graphiql", 
    "/v1/graphql", "/v2/graphql", "/v3/graphql", "/v1/graphiql", "/v2/graphiql", 
    "/v3/graphiql", "/playground", "/v1/playground", "/v2/playground", "/v3/playground", 
    "/api/v1/playground", "/api/v2/playground", "/api/v3/playground", "/console", 
    "/api/graphql", "/api/graphiql", "/explorer", "/api/v1/graphql", "/api/v2/graphql", 
    "/api/v3/graphql", "/api/v1/graphiql", "/api/v2/graphiql", "/api/v3/graphiql"
]

class GraphQLScanner:
    def __init__(self, url):
        self.url = url
        self.headers = {'Content-Type': 'application/json', 'User-Agent': HEADERS['User-Agent']}
        self.findings = []
        self.schema = None # To store introspection schema

    def send_query(self, query, variables=None):
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        try:
            response = requests.post(self.url, json=payload, headers=self.headers, timeout=10, verify=False)
            return response.json(), response.status_code
        except:
            return None, None

    def check_introspection(self):
        print("[*] Checking for Introspection...")
        query = """
        query IntrospectionQuery {
          __schema {
            queryType { fields { name args { name type { name kind ofType { name kind } } } } }
            mutationType { fields { name args { name type { name kind ofType { name kind } } } } }
            types { name }
          }
        }
        """
        data, status = self.send_query(query)
        
        if data and 'data' in data and '__schema' in data['data']:
            self.schema = data['data']['__schema'] # Save schema for later IDOR analysis
            types = self.schema['types']
            exposed_types = [t['name'] for t in types if not t['name'].startswith('__')]
            
            self.findings.append({
                "vulnerability": "Introspection Enabled",
                "severity": "Medium",
                "description": "The API exposes its entire schema structure.",
                "exposed_data": f"Found {len(exposed_types)} exposed types."
            })
        else:
            print("[-] Introspection disabled.")

    def check_field_suggestion(self):
        print("[*] Checking for Field Suggestions...")
        query = '{ __typename usernme }'
        data, status = self.send_query(query)
        if data and 'errors' in data:
            errors = str(data['errors'])
            if "Did you mean" in errors or "did you mean" in errors:
                self.findings.append({
                    "vulnerability": "Field Suggestion Enabled",
                    "severity": "Low",
                    "description": "The API reveals field names via error suggestions.",
                    "exposed_data": f"Server response: {errors[:100]}"
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
                            "description": f"Full schema exposed at: {endpoint}",
                            "exposed_data": "Manual check required."
                        })
                        return
            except:
                pass
        print("[-] No SDL leak found.")

    def check_auto_idor(self):
        """
        Automated IDOR Analysis:
        1. Uses Introspection to find queries accepting ID arguments.
        2. Tests common IDs (1, 2, admin) without authentication.
        3. Reports if data is returned (Public Exposure).
        """
        print("[*] Running Automated IDOR / Data Exposure Analysis...")
        
        # If introspection failed, we can't reliably guess query structures
        if not self.schema:
            print("[-] Skipping IDOR analysis (Introspection disabled and schema unknown).")
            return

        targets = []
        
        # Parse Schema for potential IDOR targets
        try:
            # Check QueryType
            if self.schema.get('queryType') and self.schema['queryType'].get('fields'):
                for field in self.schema['queryType']['fields']:
                    for arg in field['args']:
                        # Check if argument name contains 'id' or type is 'ID'
                        arg_name = arg['name'].lower()
                        type_name = arg.get('type', {}).get('name', '')
                        type_kind = arg.get('type', {}).get('kind', '')
                        
                        # Heuristic: Argument looks like an ID
                        if 'id' in arg_name or type_name == 'ID':
                            # Construct a basic query. 
                            # We request __typename to minimize complexity, 
                            # but for IDOR we want real data. 
                            # We try to guess a generic field selection.
                            query_str = f'query {{ {field["name"]}({arg["name"]}: "{id_val}") {{ __typename }} }}'
                            targets.append({
                                "name": field["name"],
                                "arg_name": arg["name"],
                                "query_template": f'query {{ {field["name"]}({arg["name"]}: "{{id}}") {{ __typename }} }}'
                            })
                            break # One ID arg per query is enough for testing
        except Exception as e:
            print(f"[-] Error parsing schema for IDOR: {e}")

        if not targets:
            print("[-] No ID-based queries found in schema.")
            return

        print(f"[*] Found {len(targets)} potential ID-based queries. Testing with unauthenticated requests...")

        # Common IDs to test for leaks
        test_ids = ["1", "2", "admin", "user", "me", "100"]

        for target in targets:
            for test_id in test_ids:
                query = target['query_template'].replace("{id}", test_id)
                data, status = self.send_query(query)

                if data and 'errors' not in data and 'data' in data:
                    # We got data without auth!
                    result_key = list(data['data'].keys())[0]
                    if data['data'][result_key] is not None:
                        self.findings.append({
                            "vulnerability": "Unauthenticated Data Exposure (IDOR)",
                            "severity": "High",
                            "description": f"Query '{target['name']}' returned data for ID '{test_id}' without authentication.",
                            "exposed_data": f"Query: {target['name']}({target['arg_name']}: {test_id})"
                        })
                        # Found a leak for this query, move to next query
                        break 

    def run(self):
        print(f"\n=== Scanning {self.url} ===")
        
        # Run standard checks
        self.check_introspection()
        self.check_field_suggestion()
        self.check_batching()
        self.check_sdl_leak()
        
        # Run Automated IDOR Check
        self.check_auto_idor()
        
        print("\n=== VULNERABILITY REPORT ===")
        if not self.findings:
            print("No high-confidence vulnerabilities found.")
        else:
            for i, finding in enumerate(self.findings, 1):
                print(f"\n[{i}] {finding['vulnerability']} (Severity: {finding['severity']})")
                print(f"    Description: {finding['description']}")
                if 'exposed_data' in finding:
                    print(f"    [!] EXPOSED DATA: {finding['exposed_data']}")
        print("\nScan complete.")

# --- DISCOVERY FUNCTIONS (Unchanged) ---

def is_graphql_response(response):
    content_type = response.headers.get('Content-Type', '')
    if 'json' not in content_type.lower(): return False
    text = response.text
    if '"errors"' in text and '"message"' in text: return True
    graphql_signatures = ["Must provide query string", "Syntax Error GraphQL", "GraphQL request error", "No query string supplied", "Parse error on"]
    for signature in graphql_signatures:
        if signature.lower() in text.lower(): return True
    return False

def test_endpoint(url):
    headers = {'Content-Type': 'application/json', 'User-Agent': HEADERS['User-Agent']}
    try:
        payload = {"query": "{__typename}"}
        r = requests.post(url, json=payload, headers=headers, timeout=10, verify=False)
        if r.status_code == 200:
            try:
                data = r.json()
                if "data" in data or "errors" in data: return True
            except: pass
    except: pass
    try:
        empty_payload = {}
        r = requests.post(url, json=empty_payload, headers=headers, timeout=10, verify=False)
        if r.status_code >= 400 or r.status_code == 200:
            if is_graphql_response(r): return True
    except: pass
    return False

def discover_endpoint_bruteforce(base_url):
    print(f"[*] Starting Path Brute-force on {base_url}...")
    base_url = base_url.rstrip("/")
    found_endpoints = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(test_endpoint, f"{base_url}{path}"): path for path in GRAPHQL_PATHS}
        for future in concurrent.futures.as_completed(future_to_url):
            target = f"{base_url}{future_to_url[future]}"
            try:
                if future.result():
                    print(f"    [+] FOUND: {target}")
                    found_endpoints.append(target)
            except: continue
    return found_endpoints

def crawl_website(start_url, max_depth=1):
    print(f"[*] Starting Web Crawler on {start_url}...")
    visited = set()
    to_visit = [(start_url, 0)]
    found_endpoints = set()
    session = requests.Session()
    session.headers.update(HEADERS)
    
    while to_visit:
        current_url, depth = to_visit.pop(0)
        if current_url in visited or depth > max_depth: continue
        visited.add(current_url)
        parsed_current = urlparse(current_url)
        
        if test_endpoint(current_url):
            print(f"    [+] FOUND (Crawler): {current_url}")
            found_endpoints.add(current_url)
            continue
        
        try:
            response = session.get(current_url, timeout=10, verify=False, allow_redirects=True)
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type: continue
            
            potential_paths = re.findall(r'[\"\'](.*?(?:graphql|gql|api|query).*?)[\"\']', response.text, re.IGNORECASE)
            for path in potential_paths:
                full_url = urljoin(current_url, path)
                if len(path) > 128 or path.startswith("data:"): continue
                if test_endpoint(full_url):
                    print(f"    [+] FOUND (JS/Content): {full_url}")
                    found_endpoints.add(full_url)
            
            links = re.findall(r'href=[\"\'](.*?)[\"\']', response.text)
            for link in links:
                full_link = urljoin(current_url, link)
                parsed_link = urlparse(full_link)
                if parsed_link.netloc == parsed_current.netloc:
                    if full_link not in visited: to_visit.append((full_link, depth + 1))
        except: pass
    return list(found_endpoints)

# --- MAIN EXECUTION ---

if __name__ == "__main__":
    print("==========================================")
    print("   GraphQL Auto-Discovery & Vulnerability Scanner")
    print("==========================================")
    
    target_input = input("Enter target URL or domain: ").strip()

    if not target_input:
        print("URL cannot be empty.")
        sys.exit()

    if not target_input.startswith("http"):
        target_input = "https://" + target_input

    parsed = urlparse(target_input)
    base_domain = f"{parsed.scheme}://{parsed.netloc}"
    
    valid_targets = set()

    # 1. Discovery Phase
    if test_endpoint(target_input):
        valid_targets.add(target_input)
    
    valid_targets.update(crawl_website(target_input, max_depth=1))
    valid_targets.update(discover_endpoint_bruteforce(base_domain))

    # 2. Scanning Phase
    if not valid_targets:
        print("\n[!] No GraphQL endpoints found.")
    else:
        print(f"\n[*] Starting vulnerability scan on {len(valid_targets)} endpoint(s)...")
        for target in valid_targets:
            scanner = GraphQLScanner(target)
            scanner.run()
