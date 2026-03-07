import requests      #module for making http requests
import json             #to read graphql json responses
import sys              #exit the system if something goes wrong
import urllib3        #

# 1. DISABLE SSL WARNINGS
# This prevents the console from being flooded with "InsecureRequestWarning"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class GraphQLScanner:
    def __init__(self, url):
        self.url = url
        self.headers = {'Content-Type': 'application/json'}
        self.findings = []

    def send_query(self, query, variables=None):
        """Helper to send a JSON payload to the GraphQL endpoint."""
        payload = {'query': query}
        if variables:
            payload['variables'] = variables
        
        try:
            # 2. ADD 'verify=False' TO IGNORE SSL CERTIFICATE ERRORS
            response = requests.post(self.url, json=payload, headers=self.headers, timeout=10, verify=False)
            return response.json(), response.status_code
        except requests.exceptions.RequestException as e:
            print(f"[!] Connection error: {e}")
            return None, None
        except json.JSONDecodeError:
            return None, None

    def check_introspection(self):
        """Check if introspection is enabled on production."""
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
            self.findings.append({
                "vulnerability": "Introspection Enabled",
                "severity": "Medium",
                "description": "The API exposes its entire schema structure via introspection queries."
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
                self.findings.append({
                    "vulnerability": "Field Suggestion Enabled",
                    "severity": "Low",
                    "description": "The API reveals field names via error suggestions."
                })
            else:
                print("[-] Field suggestions disabled.")
        else:
            print("[-] Could not determine field suggestion status.")

    def check_batching(self):
        """Check if query batching is allowed (potential DoS vector)."""
        print("[*] Checking for Query Batching...")
        single_query = {'query': '{ __typename }'}
        batch_payload = [single_query, single_query, single_query, single_query, single_query]
        
        try:
            # 3. ADD 'verify=False' HERE AS WELL
            response = requests.post(self.url, json=batch_payload, headers=self.headers, timeout=10, verify=False)
            if response.status_code == 200 and isinstance(response.json(), list):
                self.findings.append({
                    "vulnerability": "Query Batching Enabled",
                    "severity": "Medium",
                    "description": "The server accepts an array of queries. Bypasses rate limits."
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
                # 4. ADD 'verify=False' HERE AS WELL
                r = requests.get(endpoint, headers=self.headers, timeout=5, verify=False)
                if r.status_code == 200 and "type " in r.text and "Query" in r.text:
                    if "json" not in r.headers.get('Content-Type', ''):
                        self.findings.append({
                            "vulnerability": "SDL Leak",
                            "severity": "Medium",
                            "description": f"Full schema exposed in plain text at: {endpoint}"
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
        
        print("\n=== REPORT ===")
        if not self.findings:
            print("No high-confidence vulnerabilities found.")
        else:
            for i, finding in enumerate(self.findings, 1):
                print(f"\n[{i}] {finding['vulnerability']} (Severity: {finding['severity']})")
                print(f"    -> {finding['description']}")
        print("\nScan complete.")

if __name__ == "__main__":
    print("--- GraphQL Vulnerability Detector ---")
    target = input("Enter the target GraphQL URL: ").strip()

    # Validation
    if not target:
        print("URL cannot be empty. Exiting.")
        sys.exit()
    
    # Fix for users who forget http/https
    if not target.startswith("http"):
        print("[!] Invalid URL. Please start with http:// or https://")
        sys.exit()

    scanner = GraphQLScanner(target)
    scanner.run()
