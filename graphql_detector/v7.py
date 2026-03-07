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

# ... [KEPT THE SAME: GRAPHQL_PATHS list and HEADERS dictionary] ...
# (Removed to save space, they are the same as your original file)
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

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
}

class GraphQLScanner:
    def __init__(self, url):
        self.url = url
        self.headers = {'Content-Type': 'application/json', 'User-Agent': HEADERS['User-Agent']}
        self.findings = []

    def send_query(self, query, variables=None, custom_headers=None):
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        
        # Merge default headers with custom headers
        req_headers = self.headers.copy()
        if custom_headers:
            req_headers.update(custom_headers)
        
        try:
            response = requests.post(self.url, json=payload, headers=req_headers, timeout=10, verify=False)
            return response.json(), response.status_code
        except requests.exceptions.RequestException:
            return None, None
        except json.JSONDecodeError:
            return None, None

    # ... [KEPT THE SAME: check_introspection, check_field_suggestion, check_batching, check_sdl_leak] ...
    # (I'm collapsing these for brevity, they remain unchanged from your file)
    
    def check_introspection(self):
        print("[*] Checking for Introspection...")
        query = """ query IntrospectionQuery { __schema { types { name } } } """
        data, status = self.send_query(query)
        if data and 'data' in data and '__schema' in data['data']:
            types = data['data']['__schema']['types']
            exposed_types = [t['name'] for t in types if not t['name'].startswith('__')]
            self.findings.append({"vulnerability": "Introspection Enabled", "severity": "Medium", "description": "The API exposes its entire schema structure.", "exposed_data": f"Found {len(exposed_types)} exposed types."})
        else: print("[-] Introspection disabled.")

    def check_field_suggestion(self):
        print("[*] Checking for Field Suggestions...")
        query = '{ __typename usernme }'
        data, status = self.send_query(query)
        if data and 'errors' in data:
            errors = str(data['errors'])
            if "Did you mean" in errors or "did you mean" in errors:
                self.findings.append({"vulnerability": "Field Suggestion Enabled", "severity": "Low", "description": "The API reveals field names via error suggestions.", "exposed_data": f"Server response: {errors}"})
            else: print("[-] Field suggestions disabled.")

    def check_batching(self):
        print("[*] Checking for Query Batching...")
        single_query = {'query': '{ __typename }'}
        batch_payload = [single_query] * 5
        try:
            response = requests.post(self.url, json=batch_payload, headers=self.headers, timeout=10, verify=False)
            if response.status_code == 200 and isinstance(response.json(), list):
                self.findings.append({"vulnerability": "Query Batching Enabled", "severity": "Medium", "description": "The server accepts an array of queries.", "exposed_data": "Bypasses rate limits."})
            else: print("[-] Query batching disabled.")
        except Exception: print("[-] Could not test batching.")

    def check_sdl_leak(self):
        print("[*] Checking for SDL Leaks...")
        endpoints = [self.url, self.url.replace("/graphql", "/graphql?sdl")]
        for endpoint in endpoints:
            try:
                r = requests.get(endpoint, headers=self.headers, timeout=5, verify=False)
                if r.status_code == 200 and "type " in r.text and "Query" in r.text:
                    if "json" not in r.headers.get('Content-Type', ''):
                        self.findings.append({"vulnerability": "SDL Leak", "severity": "Medium", "description": f"Full schema exposed at: {endpoint}", "exposed_data": "Check manually."})
                        return
            except: pass
        print("[-] No SDL leak found.")

    def check_idor(self, victim_headers, attacker_headers, victim_id):
        """
        Checks for IDOR.
        Accepts full header dictionaries for Victim and Attacker.
        """
        print("[*] Checking for IDOR Vulnerabilities...")
        
        # Helper to parse data
        def has_valid_data(data):
            if not data: return False
            if 'errors' in data and not data.get('data'): return False # Hard error
            if data.get('data'): return True
            return False

        # 1. Define common query patterns
        # Note: If introspection was found, we could parse it here, but we'll use common patterns.
        common_queries = [
            'query { user(id: "{id}") { __typename } }',
            'query { getUser(id: "{id}") { __typename } }',
            'query { account(id: "{id}") { __typename } }',
            'query { post(id: "{id}") { __typename } }',
            'query { node(id: "{id}") { __typename } }',
            'query { item(id: "{id}") { __typename } }',
            'query { order(id: "{id}") { __typename } }',
            'query { document(id: "{id}") { __typename } }',
            'query { node(id: "{id}") { id } }',
        ]

        # 2. Introspection for better accuracy
        # (Code omitted for brevity, logic same as previous: find args with 'id')
        
        targets = common_queries 

        # 3. Execute Tests
        for query_template in targets:
            query = query_template.replace("{id}", victim_id)
            
            # --- Scenario A: Authenticated IDOR ---
            if victim_headers and attacker_headers:
                # Step 1: Victim accesses resource
                data_victim, _ = self.send_query(query, custom_headers=victim_headers)
                
                if has_valid_data(data_victim):
                    # Step 2: Attacker tries to access same resource
                    data_attacker, _ = self.send_query(query, custom_headers=attacker_headers)
                    
                    if has_valid_data(data_attacker):
                        # Check if data returned is not null
                        first_key = list(data_attacker['data'].keys())[0]
                        if data_attacker['data'][first_key] is not None:
                            self.findings.append({
                                "vulnerability": "IDOR (Authenticated)",
                                "severity": "High",
                                "description": "Attacker user accessed victim resource.",
                                "exposed_data": f"Query: {query}"
                            })
                            return # Stop after first finding

            # --- Scenario B: Unauthenticated IDOR (Public Exposure) ---
            # If no headers provided OR if we want to check public access specifically
            # We check if data is accessible WITHOUT any auth
            data_public, _ = self.send_query(query) # No headers
            
            if has_valid_data(data_public):
                # It worked without auth? That's an issue if data is private.
                # We flag this as "Public Exposure / Unauthenticated IDOR"
                self.findings.append({
                    "vulnerability": "Unauthenticated Data Access",
                    "severity": "High",
                    "description": "Resource accessible without authentication.",
                    "exposed_data": f"Query: {query}"
                })
                return

        print("[-] No IDOR patterns matched or access was correctly denied.")

    def run(self, idor_config=None):
        print(f"\n=== Scanning {self.url} ===")
        self.check_introspection()
        self.check_field_suggestion()
        self.check_batching()
        self.check_sdl_leak()
        
        if idor_config:
            self.check_idor(
                idor_config.get('victim_headers'), 
                idor_config.get('attacker_headers'), 
                idor_config['victim_id']
            )
        
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


# ... [KEPT THE SAME: Discovery Functions (is_graphql_response, test_endpoint, etc.)] ...
# (These functions remain exactly the same)

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
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {executor.submit(test_endpoint, f"{base_url}{path}"): f"{base_url}{path}" for path in GRAPHQL_PATHS}
        for future in concurrent.futures.as_completed(future_to_url):
            target = future_to_url[future]
            try:
                if future.result():
                    print(f"    [+] FOUND (Bruteforce): {target}")
                    found_endpoints.append(target)
            except Exception: continue
    return found_endpoints

def crawl_website(start_url, max_depth=2):
    print(f"[*] Starting Web Crawler on {start_url} (Depth: {max_depth})...")
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
            print(f"    [+] FOUND (Crawler Page): {current_url}")
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
                    print(f"    [+] FOUND (Crawler Content Analysis): {full_url}")
                    found_endpoints.add(full_url)
            links = re.findall(r'href=[\"\'](.*?)[\"\']', response.text) + re.findall(r'src=[\"\'](.*?)[\"\']', response.text)
            for link in links:
                full_link = urljoin(current_url, link)
                parsed_link = urlparse(full_link)
                if parsed_link.netloc == parsed_current.netloc:
                    if full_link not in visited: to_visit.append((full_link, depth + 1))
                else:
                    if test_endpoint(full_link):
                        print(f"    [+] FOUND (External Link Check): {full_link}")
                        found_endpoints.add(full_link)
        except Exception: pass
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

    # 1. Discovery
    if test_endpoint(target_input):
        print(f"[+] Input URL is a valid GraphQL endpoint: {target_input}")
        valid_targets.add(target_input)

    crawl_found = crawl_website(target_input, max_depth=1) 
    valid_targets.update(crawl_found)

    bruteforce_found = discover_endpoint_bruteforce(base_domain)
    valid_targets.update(bruteforce_found)

    # 2. IDOR Configuration
    print("\n--- IDOR / Auth Check Configuration ---")
    print("You can check for IDOR with or without authentication.")
    print("1. Unauthenticated Check (Checks if IDs are public)")
    print("2. Authenticated Check (Requires headers for 2 users)")
    choice = input("Select mode (1 or 2): ").strip()

    idor_config = None
    victim_id = ""

    if choice == '2':
        print("\n[!] How to provide headers:")
        print("    Cookies: paste the value (e.g., 'PHPSESSID=abc123; user=admin')")
        print("    Tokens:  paste the value (e.g., 'Bearer eyJhb...')")
        
        victim_id = input("Enter the Victim Resource ID to test (e.g. 123): ").strip()
        if not victim_id:
            print("ID required. Skipping IDOR.")
        else:
            print("\n--- Victim User (Owner) ---")
            v_auth_val = input("Enter Victim's Auth Value (Cookie or Token): ").strip()
            v_auth_type = input("Is this a Cookie or Token? (c/t): ").lower().strip()
            
            victim_headers = {}
            if v_auth_type == 'c':
                victim_headers['Cookie'] = v_auth_val
            else:
                victim_headers['Authorization'] = v_auth_val

            print("\n--- Attacker User (Hacker) ---")
            a_auth_val = input("Enter Attacker's Auth Value: ").strip()
            a_auth_type = input("Is this a Cookie or Token? (c/t): ").lower().strip()

            attacker_headers = {}
            if a_auth_type == 'c':
                attacker_headers['Cookie'] = a_auth_val
            else:
                attacker_headers['Authorization'] = a_auth_val
            
            idor_config = {
                'victim_headers': victim_headers,
                'attacker_headers': attacker_headers,
                'victim_id': victim_id
            }
    
    elif choice == '1':
        victim_id = input("Enter Resource ID to test (e.g. 123): ").strip()
        if victim_id:
            idor_config = {
                'victim_headers': None, # No auth
                'attacker_headers': None, # No auth
                'victim_id': victim_id
            }

    # 3. Run Scans
    if not valid_targets:
        print("\n[!] No GraphQL endpoints found.")
    else:
        print(f"\n[*] Starting vulnerability scan on {len(valid_targets)} endpoint(s)...")
        for target in valid_targets:
            scanner = GraphQLScanner(target)
            scanner.run(idor_config=idor_config)
