import requests
import json
import sys
import urllib3

# Disable SSL warnings for https scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class GraphQLScanner:
    def __init__(self, url):
        self.url = url
        self.headers = {'Content-Type': 'application/json'}
        self.findings = []

    def send_query(self, query, variables=None):
        payload = {'query': query}
        print(payload,"\n")
        if variables:
            payload['variables'] = variables
        
        try:
            response = requests.post(self.url, json=payload, headers=self.headers, timeout=10, verify=False)
            return response.json(), response.status_code
        except requests.exceptions.RequestException as e:
            print(f"[!] Connection error: {e}")
            return None, None
        except json.JSONDecodeError:
            return None, None

    def check_introspection(self):
        """Check if introspection is enabled and show exposed types."""
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
            # Extract the type names to show what was exposed
            types = data['data']['__schema']['types']
            # Filter out built-in types (starting with __) for a cleaner list
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
        """Check if the API suggests correct field names on typos."""
        print("[*] Checking for Field Suggestions...")
        query = '{ __typename usernme }'
        data, status = self.send_query(query)

        if data and 'errors' in data:
            errors = str(data['errors'])
            if "Did you mean" in errors or "did you mean" in errors:
                # Extract the specific suggestion to show proof
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
        """Check if query batching is allowed."""
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
        """Check if the SDL is exposed at common endpoints."""
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
                        # Show a snippet of the leaked schema
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
                # Print the exposed data if it exists
                if 'exposed_data' in finding:
                    print(f"    [!] EXPOSED DATA: {finding['exposed_data']}")
        print("\nScan complete.")

if __name__ == "__main__":
    print("--- GraphQL Vulnerability Detector ---")
    target = input("Enter the target GraphQL URL: ").strip()

    if not target:
        print("URL cannot be empty. Exiting.")
        sys.exit()
    
    if not target.startswith("http"):
        print("[!] Invalid URL. Please start with http:// or https://")
        sys.exit()

    scanner = GraphQLScanner(target)
    scanner.run()
