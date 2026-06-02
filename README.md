<h1>GraphQL Vulnerability Detector</h1>

<img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTF5e78TxsPQ-rqevdXi4ZrDTNoSkQqg6A2pg&s" width=100% height=40%>

<p>GraphQLi is an advanced, multi-threaded security auditing tool designed to discover GraphQL endpoints and analyze them for critical security misconfigurations, information leakage, and potential vulnerabilities.It features a hybrid discovery engine (combining web crawling and path brute-forcing) and a comprehensive vulnerability scanner that supports deep fingerprinting of the underlying GraphQL engine.</p>

<h3>🚀 Key Features</h3>
<ol>
  <li><b>Smart Endpoint Discovery</b></li>
The tool automatically attempts to locate hidden or undocumented GraphQL APIs if the direct URL is not a valid endpoint.
<ul>
  <li><b>Web Crawling</b>: Parses HTML and JavaScript files to find relative API paths hidden in client-side code.</li>
  <li><b>Path Brute-Forcing</b>: Concurrently checks a list of 30+ common GraphQL paths (e.g., /graphql, /api, /graphiql, /console).</li>
  <li><b>Strict Validation</b>: Uses both loose and strict validation logic to minimize false positives by verifying that the endpoint responds with valid GraphQL JSON structures.</li>
</ul>
<li><b>Comprehensive Vulnerability Scanning</b></li>
Once an endpoint is validated, GraphQLi runs a suite of security checks:
<ul>
  <li><b>Introspection Analysis</b>: Attempts to dump the full API schema. If successful, it identifies Queries, Mutations, and Types, saving the schema to a local JSON file with restricted permissions (0o600).</li>
  <li><b>Automated IDOR Detection</b>: Analyzes the schema (or uses heuristic guessing) to identify fields accepting "ID" arguments. It then probes these with test IDs (1, 2, 100) to check for unauthenticated data exposure.</li>
  <li><b>Version Fingerprinting: Actively identifies the specific GraphQL engine (Apollo, Hasura, Graphene, AWS AppSync, etc.) by analyzing:</b></li>
  <ul>
    <li><b>HTTP Headers</b> (X-Powered-By, X-Apollo-Server-Version)</li>
    <li><b>Error message formatting</b></li>
    <li><b>Schema structure</b> (e.g., _Service for Apollo Federation)</b></li>
    <li><b>Specific metadata fields</b> (version, build)</b></li>
  </ul>
  <li><b>Attack Surface Detection:</b></li>
    <ul>
      <li><b>Query Batching:</b> Checks if the server accepts arrays of queries (potential DoS vector).</li>
      <li><b>Field Suggestions</b>: Probes for error messages that leak valid field names.</li>
      <li><b>SDL Leaks:</b> Checks for plain text schema definition language leaks via GET requests.</li>
    </ul>
</ul>
  <li><b>Security & Hardening</b></li>
  The tool is built with a security-first mindset to prevent accidental damage during scans:
  <ul>
    <li><b>SSRF Protection</b>: Automatically resolves hostnames and blocks requests to private, internal, or loopback IPs (e.g., 169.254.169.254, localhost, 192.168.x.x) to prevent Server-Side Request Forgery.</li>
    <li><b>Secure File Handling</b>: Generated schema files are written with exclusive creation flags and restrictive user-only permissions to prevent local information leakage.</li>
  </ul>
</ol>

<h3>🛠️ Installation</h3>
<b>Requirements:</b></br>
<p>Python 3.x</br>  
requests library</p>

<b>Setup:</b>

    pip install requests

<h3>💻 Usage</h3>
Run the script and provide the target URL. The tool handles HTTP/HTTPS schemes automatically.

    python3 graphqli_v17.4.py
Interactive Prompt:

    Enter target URL or domain: example.com
<b>How it works:</b>
<ul>
  <li><b>Input Validation:</b> The tool checks if the input is a valid, non-malicious URL.</li>
  <li><b>Direct Check:</b> If the URL is a valid GraphQL endpoint, scanning starts immediately.</li>
  <li><b>Discovery Mode:</b> If the URL is a standard website, the tool crawls the page and brute-forces paths to find the API.</li>
  <li><b>Reporting:</b> A detailed vulnerability report is generated in the console, and schemas are saved to the disk.</li>
</ul>

<h3>📊 Example Output</h3>
<img src="">
