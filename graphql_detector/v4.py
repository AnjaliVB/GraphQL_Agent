import requests
import json
import sys
import urllib3
import concurrent.futures
import re
from urllib.parse import urlparse, urljoin

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Expanded list of common paths
GRAPHQL_PATHS = [
    "/graphql", "/graphql/", 
    "/api/graphql", "/api/graphql/",
    "/v1/graphql", "/v2/graphql", "/v3/graphql",
    "/query", "/gql", "/gql/",
    "/api", "/api/v1", "/api/v2",
    "/graphql.php", "/graphql-console",
    "/graphiql", "/playground",
    "/altair", "/explorer",
    "/services/graphql", "/graphql/schema",
    "/console", "/debug/graphql",
    "/api/public", "/api/internal",
    "/rest/graphql", "/_graphql"
]

class GraphQLScanner:
    def __init__(self, url):
        self.url = url
        self.headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
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
    headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
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

def discover_endpoint_bruteforce(base_url):
    """Brute forces common paths to find GraphQL endpoints."""
    print(f"[*] Starting Path Brute-force on {base_url}...")
    base_url = base_url.rstrip("/")
    found_endpoints = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {}
        for path in GRAPHQL_PATHS:
            target = f"{base_url}{path}"
            future_to_url[executor.submit(test_endpoint, target)] = target
        
        for future in concurrent.futures.as_completed(future_to_url):
            target = future_to_url[future]
            is_valid = future.result()
            if is_valid:
                print(f"    [+] FOUND (Bruteforce): {target}")
                found_endpoints.append(target)
    
    return found_endpoints

def discover_endpoints_in_js(base_url):
    """Crawls HTML and JS files to find hardcoded endpoints."""
    print(f"[*] Analyzing JavaScript Code for hidden endpoints...")
    found_endpoints = set()
    
    try:
        # 1. Fetch the main page HTML
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(base_url, headers=headers, timeout=10, verify=False)
        response.raise_for_status()
        html_content = response.text
        
        # 2. Regex to find script sources
        # Matches src="..." and src='...'
        js_files = re.findall(r'src=[\"\'](.*?\.js.*?)[\"\']', html_content)
        
        # Also find potential endpoints directly in HTML (sometimes hardcoded in inline scripts)
        # Regex looks for strings containing "graphql", "api", "gql"
        html_potential_paths = re.findall(r'[\"\'](.*?(?:graphql|gql|api).*?)[\"\']', html_content, re.IGNORECASE)
        
        for path in html_potential_paths:
            full_url = urljoin(base_url, path)
            if test_endpoint(full_url):
                print(f"    [+] FOUND (HTML Analysis): {full_url}")
                found_endpoints.add(full_url)

        # 3. Analyze external JS files
        print(f"    [~] Found {len(js_files)} JS files to analyze...")
        
        for js_path in js_files:
            # Resolve relative URLs
            js_url = urljoin(base_url, js_path)
            
            try:
                js_resp = requests.get(js_url, headers=headers, timeout=10, verify=False)
                if js_resp.status_code == 200:
                    # Regex to find strings that look like endpoints
                    # Matches "/api/...", "https://...", "...graphql..."
                    # We are looking for quoted strings.
                    matches = re.findall(r'[\"\'](.*?(?:graphql|gql|api|query|endpoint).*?)[\"\']', js_resp.text, re.IGNORECASE)
                    
                    for match in matches:
                        # Filter out obvious false positives (data URIs, huge strings)
                        if len(match) > 256 or match.startswith("data:"):
                            continue
                            
                        # Construct full URL
                        full_match_url = urljoin(base_url, match)
                        
                        # Test it
                        if test_endpoint(full_match_url):
                            print(f"    [+] FOUND (JS Analysis): {full_match_url}")
                            found_endpoints.add(full_match_url)
            except Exception:
                continue

    except Exception as e:
        print(f"[-] Error during JS analysis: {e}")
        
    return list(found_endpoints)

# --- MAIN EXECUTION ---

if __name__ == "__main__":
    print("==========================================")
    print("   GraphQL Advanced Discovery Scanner")
    print("==========================================")
    
    target_input = input("Enter target URL or domain: ").strip()

    if not target_input:
        print("URL cannot be empty.")
        sys.exit()

    # Fix protocol if missing
    if not target_input.startswith("http"):
        target_input = "https://" + target_input

    parsed = urlparse(target_input)
    base_domain = f"{parsed.scheme}://{parsed.netloc}"

    valid_targets = set()

    # 1. Check if input is already a valid endpoint
    if test_endpoint(target_input):
        print(f"[+] Input URL is a valid GraphQL endpoint: {target_input}")
        valid_targets.add(target_input)

    # 2. Run JS Analysis (Finds hidden/unlisted paths)
    js_found = discover_endpoints_in_js(target_input)
    valid_targets.update(js_found)

    # 3. Run Bruteforce (Standard paths)
    bruteforce_found = discover_endpoint_bruteforce(base_domain)
    valid_targets.update(bruteforce_found)

    # 4. Run Vulnerability Scans
    if not valid_targets:
        print("\n[!] No GraphQL endpoints found.")
    else:
        print(f"\n[*] Starting vulnerability scan on {len(valid_targets)} endpoint(s)...")
        for target in valid_targets:
            scanner = GraphQLScanner(target)
            scanner.run()
