import requests
import json
import sys
import urllib3
import concurrent.futures
from urllib.parse import urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common paths for discovery
GRAPHQL_PATHS = [
    "/graphql", "/graphql/", 
    "/api/graphql", "/api/graphql/",
    "/v1/graphql", "/v2/graphql",
    "/query", "/gql",
    "/api", "/api/v1",
    "/graphql.php", "/graphql-console"
]

class GraphQLScanner:
    def __init__(self, url):
        self.url = url
        self.headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
        self.findings = []

    def send_query(self, query, variables=None):
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        
        try:
            response = requests.post(self.url, json=payload, headers=self.headers, timeout=10, verify=False)
            return response.json(), response.status_code
        except requests.exceptions.RequestException:
            return None, None
        except json.JSONDecodeError:
            return None, None

    def check_introspection(self):
        print("[*] Checking for Introspection...")
        query = """
        query IntrospectionQuery {
          __schema {
            types {
              name
            }
          }
        }
        """
        data, status = self.send_query(query)
        
        if data and 'data' in data and '__schema' in data['data']:
            types = data['data']['__schema']['types']
            exposed_types = [t['name'] for t in types if not t['name'].startswith('__')]
            
            self.findings.append({
                "vulnerability": "Introspection Enabled",
                "severity": "Medium",
                "description": "The API exposes its entire schema structure.",
                "exposed_data": f"Found {len(exposed_types)} exposed types: {', '.join(exposed_types[:10])}..."
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
                    "exposed_data": f"Server response: {errors}"
                })
            else:
                print("[-] Field suggestions disabled.")
        else:
            print("[-] Could not determine field suggestion status.")

    def check_batching(self):
        print("[*] Checking for Query Batching...")
        single_query = {'query': '{ __typename }'}
        batch_payload = [single_query, single_query, single_query, single_query, single_query]
        
        try:
            response = requests.post(self.url, json=batch_payload, headers=self.headers, timeout=10, verify=False)
            if response.status_code == 200 and isinstance(response.json(), list):
                self.findings.append({
                    "vulnerability": "Query Batching Enabled",
                    "severity": "Medium",
                    "description": "The server accepts an array of queries. Bypasses rate limits.",
                    "exposed_data": f"Server accepted a batch of {len(batch_payload)} queries in one request."
                })
            else:
                print("[-] Query batching disabled.")
        except Exception:
            print("[-] Could not test batching.")

    def check_sdl_leak(self):
        print("[*] Checking for SDL Leaks...")
        endpoints = [
            self.url, 
            self.url.replace("/graphql", "/graphql?sdl"),
        ]
        
        for endpoint in endpoints:
            try:
                r = requests.get(endpoint, headers=self.headers, timeout=5, verify=False)
                if r.status_code == 200 and "type " in r.text and "Query" in r.text:
                    if "json" not in r.headers.get('Content-Type', ''):
                        snippet = r.text.replace('\n', ' ')[:100]
                        self.findings.append({
                            "vulnerability": "SDL Leak",
                            "severity": "Medium",
                            "description": f"Full schema exposed in plain text at: {endpoint}",
                            "exposed_data": f"Schema snippet: {snippet}..."
                        })
                        return
            except:
                pass
        print("[-] No SDL leak found.")

    def run(self):
        print(f"\n=== Scanning {self.url} ===\n")
        self.check_introspection()
        self.check_field_suggestion()
        self.check_batching()
        self.check_sdl_leak()
        
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

# --- DISCOVERY FUNCTIONS ---

def test_endpoint(url):
    """Tests if a single URL is a valid GraphQL endpoint."""
    payload = {"query": "{__typename}"}
    headers = {'Content-Type': 'application/json'}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=5, verify=False)
        if r.status_code == 200:
            try:
                data = r.json()
                if "data" in data or "errors" in data:
                    return True
            except:
                pass
    except:
        pass
    return False

def discover_endpoint(base_url):
    """Brute forces common paths to find GraphQL endpoints."""
    print(f"[*] Starting Endpoint Discovery on {base_url}...")
    base_url = base_url.rstrip("/")
    found_endpoints = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {}
        for path in GRAPHQL_PATHS:
            target = f"{base_url}{path}"
            future_to_url[executor.submit(test_endpoint, target)] = target
        
        for future in concurrent.futures.as_completed(future_to_url):
            target = future_to_url[future]
            is_valid = future.result()
            if is_valid:
                print(f"    [+] FOUND: {target}")
                found_endpoints.append(target)
    
    return found_endpoints

# --- MAIN EXECUTION ---

if __name__ == "__main__":
    print("==========================================")
    print("   GraphQL Auto-Discovery & Vulnerability Scanner")
    print("==========================================")
    
    target_input = input("Enter target URL or domain: ").strip()

    if not target_input:
        print("URL cannot be empty.")
        sys.exit()

    # Fix protocol if missing
    if not target_input.startswith("http"):
        target_input = "https://" + target_input

    # 1. Check if the input itself is already a valid endpoint
    # This handles cases where user provides the full URL directly
    valid_targets = []
    if test_endpoint(target_input):
        print(f"[+] Input URL is a valid GraphQL endpoint: {target_input}")
        valid_targets.append(target_input)
    
    # 2. Parse base domain and run discovery regardless
    # (In case the user input a specific path, we still check the root domain)
    parsed = urlparse(target_input)
    base_domain = f"{parsed.scheme}://{parsed.netloc}"
    
    # Only run discovery if we haven't already scanned the specific paths
    # or if we want to find ALL endpoints on the domain.
    print(f"[*] Scanning base domain for other endpoints...")
    discovered = discover_endpoint(base_domain)
    
    # Combine and deduplicate
    for d in discovered:
        if d not in valid_targets:
            valid_targets.append(d)

    # 3. Run Vulnerability Scans on all found endpoints
    if not valid_targets:
        print("\n[!] No GraphQL endpoints found.")
    else:
        print(f"\n[*] Starting vulnerability scan on {len(valid_targets)} endpoint(s)...")
        for target in valid_targets:
            scanner = GraphQLScanner(target)
            scanner.run()
