import requests
import json
import sys
import urllib3
import concurrent.futures
import re
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Expanded list of common paths
GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/", 
    "/api/graphql",
    "/api/graphql/",
    "/v1/graphql",
    "/v2/graphql",
    "/v3/graphql",
    "/query",
    "/gql",
    "/gql/",
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql.php",
    "/graphql-console",
    "/graphiql",
    "/playground",
    "/altair",
    "/explorer",
    "/services/graphql",
    "/graphql/schema",
    "/console",
    "/debug/graphql",
    "/api/public",
    "/api/internal",
    "/rest/graphql",
    "/_graphql",
    "/api/data",
    "/api/query/graphql",
    "/graphiql",
    "/v1/graphql",
    "/v2/graphql",
    "/v3/graphql",
    "/v1/graphiql",
    "/v2/graphiql",
    "/v3/graphiql",
    "/playground",
    "/v1/playground",
    "/v2/playground",
    "/v3/playground",
    "/api/v1/playground",
    "/api/v2/playground",
    "/api/v3/playground",
    "/console",
    "/api/graphql",
    "/api/graphiql",
    "/explorer",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/api/v3/graphql",
    "/api/v1/graphiql",
    "/api/v2/graphiql",
    "/api/v3/graphiql"
]

# Global headers
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
}

class GraphQLScanner:
    def __init__(self, url):
        self.url = url
        self.headers = {'Content-Type': 'application/json', 'User-Agent': HEADERS['User-Agent']}
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

def is_graphql_response(response):
    content_type = response.headers.get('Content-Type', '')
    if 'json' not in content_type.lower():
        return False
    text = response.text
    if '"errors"' in text and '"message"' in text:
        return True
    graphql_signatures = [
        "Must provide query string", 
        "Syntax Error GraphQL",
        "GraphQL request error",
        "No query string supplied",
        "Parse error on"
    ]
    for signature in graphql_signatures:
        if signature.lower() in text.lower():
            return True
    return False

def test_endpoint(url):
    """Tests if a single URL is a valid GraphQL endpoint."""
    headers = {'Content-Type': 'application/json', 'User-Agent': HEADERS['User-Agent']}
    
    # Strategy 1: Standard valid query
    try:
        payload = {"query": "{__typename}"}
        r = requests.post(url, json=payload, headers=headers, timeout=10, verify=False)
        if r.status_code == 200:
            try:
                data = r.json()
                if "data" in data or "errors" in data:
                    return True
            except:
                pass
    except:
        pass

    # Strategy 2: Error-Based Detection
    try:
        empty_payload = {}
        r = requests.post(url, json=empty_payload, headers=headers, timeout=10, verify=False)
        if r.status_code >= 400 or r.status_code == 200:
            if is_graphql_response(r):
                return True
    except:
        pass

    return False

def discover_endpoint_bruteforce(base_url):
    """Brute forces common paths."""
    print(f"[*] Starting Path Brute-force on {base_url}...")
    base_url = base_url.rstrip("/")
    found_endpoints = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {}
        for path in GRAPHQL_PATHS:
            target = f"{base_url}{path}"
            future_to_url[executor.submit(test_endpoint, target)] = target
        
        for future in concurrent.futures.as_completed(future_to_url):
            target = future_to_url[future]
            try:
                is_valid = future.result()
                if is_valid:
                    print(f"    [+] FOUND (Bruteforce): {target}")
                    found_endpoints.append(target)
            except Exception:
                continue
    return found_endpoints

def crawl_website(start_url, max_depth=2):
    """
    Crawls the website starting from start_url.
    Checks every link found for GraphQL associations.
    """
    print(f"[*] Starting Web Crawler on {start_url} (Depth: {max_depth})...")
    
    visited = set()
    to_visit = [(start_url, 0)] # (url, depth)
    found_endpoints = set()
    
    session = requests.Session()
    session.headers.update(HEADERS)

    while to_visit:
        current_url, depth = to_visit.pop(0)
        
        # Skip if visited or too deep
        if current_url in visited or depth > max_depth:
            continue
        
        visited.add(current_url)
        parsed_current = urlparse(current_url)

        # 1. Check if the current page itself is a GraphQL endpoint
        # (Sometimes people put graphql at /dashboard or /api/data without explicit /graphql)
        if test_endpoint(current_url):
            print(f"    [+] FOUND (Crawler Page): {current_url}")
            found_endpoints.add(current_url)
            # Don't crawl an API endpoint for links, just continue
            continue

        try:
            # 2. Fetch the page content
            response = session.get(current_url, timeout=10, verify=False, allow_redirects=True)
            content_type = response.headers.get('Content-Type', '')
            
            # Only parse HTML pages
            if 'text/html' not in content_type:
                continue

            # 3. Analyze HTML Content for hidden paths (Regex approach)
            # Looks for strings in <script> tags or attributes that look like paths
            potential_paths = re.findall(r'[\"\'](.*?(?:graphql|gql|api|query).*?)[\"\']', response.text, re.IGNORECASE)
            
            for path in potential_paths:
                full_url = urljoin(current_url, path)
                # Filter out data URIs and huge strings
                if len(path) > 128 or path.startswith("data:"):
                    continue
                
                if test_endpoint(full_url):
                    print(f"    [+] FOUND (Crawler Content Analysis): {full_url}")
                    found_endpoints.add(full_url)

            # 4. Extract Links (href, src) to visit next
            # Using simple regex to avoid BeautifulSoup dependency, though BS4 is better
            links = re.findall(r'href=[\"\'](.*?)[\"\']', response.text) + \
                    re.findall(r'src=[\"\'](.*?)[\"\']', response.text)
            
            for link in links:
                # Resolve relative URL
                full_link = urljoin(current_url, link)
                parsed_link = urlparse(full_link)

                # Only crawl same-domain links to prevent crawling the whole internet
                if parsed_link.netloc == parsed_current.netloc:
                    if full_link not in visited:
                        to_visit.append((full_link, depth + 1))
                else:
                    # Optional: Check external links for endpoints but don't crawl them
                    if test_endpoint(full_link):
                        print(f"    [+] FOUND (External Link Check): {full_link}")
                        found_endpoints.add(full_link)

        except Exception as e:
            # Ignore connection errors on specific pages
            pass

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

    # Fix protocol if missing
    if not target_input.startswith("http"):
        target_input = "https://" + target_input

    parsed = urlparse(target_input)
    base_domain = f"{parsed.scheme}://{parsed.netloc}"
    
    valid_targets = set()

    # 1. Check Input URL
    if test_endpoint(target_input):
        print(f"[+] Input URL is a valid GraphQL endpoint: {target_input}")
        valid_targets.add(target_input)

    # 2. Run Crawler (The new feature)
    # Increases discovery by actually reading page content and following links
    crawl_found = crawl_website(target_input, max_depth=1) # Depth 1 keeps it fast
    valid_targets.update(crawl_found)

    # 3. Run Bruteforce (Standard checks)
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
