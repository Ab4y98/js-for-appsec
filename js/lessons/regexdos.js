window.LESSONS = window.LESSONS || {};
window.LESSONS.regexdos = `

<h1 class="lesson-title">Lab 12: ReDoS (Regular Expression Denial of Service)</h1>

<p class="lesson-subtitle">
  You are going to learn how a single regular expression can bring down an entire Node.js server.
  Not by exploiting a bug in the runtime. Not by exhausting memory. By simply sending a carefully
  crafted string that makes the regex engine do exponentially more work than it should. This is one
  of those vulnerabilities that sounds academic until you realize it has taken down Cloudflare.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> Why Regex Is Dangerous in JavaScript</h2>

<p>
  Before we look at any code, I need you to internalize one fact about JavaScript: it is
  single-threaded. The event loop processes one operation at a time. When your Node.js server is
  evaluating a regular expression, it is not doing anything else. It is not handling other HTTP
  requests. It is not responding to health checks. It is not processing WebSocket messages. It is
  sitting there, grinding through regex backtracking, while every other connection waits.
</p>

<p>
  In a language like Java or Go, a slow regex blocks one thread out of many. The server keeps
  handling other requests on other threads. It is bad, but it is not catastrophic. In Node.js, a
  slow regex blocks the ONLY thread. Your entire application freezes. Every connected user
  experiences a timeout. Your load balancer starts returning 502s. Your monitoring fires alerts.
  And the attacker accomplished all of this with a single HTTP request containing a carefully
  chosen string.
</p>

<p>
  This is what makes ReDoS particularly devastating in the Node.js ecosystem. The single-threaded
  architecture that makes Node great for I/O-heavy workloads is the same architecture that makes
  it uniquely vulnerable to computational attacks. Any operation that blocks the event loop for
  more than a few milliseconds is a problem. A regex that blocks it for 30 seconds is a full
  denial of service.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Build a Vulnerable Email Validator</h2>

<p>
  Let me show you a scenario I have encountered in real applications. Someone needs to validate
  email addresses on the server side. They search for "email regex" and find a complex pattern
  that claims to handle all the edge cases of RFC 5322. They drop it into a route handler and
  move on. Here is what that looks like:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/validate.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> router <span class="op">=</span> express.<span class="fn">Router</span>();

<span class="cmt">// VULNERABLE: nested quantifiers cause catastrophic backtracking</span>
<span class="kw">const</span> EMAIL_REGEX <span class="op">=</span> /^([a-zA-Z0-9])(([-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}[a-z]{2,}\$/;

router.<span class="fn">post</span>(<span class="str">'/validate-email'</span>, (req, res) <span class="op">=></span> {
  <span class="kw">const</span> { email } <span class="op">=</span> req.body;

  <span class="kw">if</span> (EMAIL_REGEX.<span class="fn">test</span>(email)) {
    res.<span class="fn">json</span>({ valid: <span class="kw">true</span> });
  } <span class="kw">else</span> {
    res.<span class="fn">json</span>({ valid: <span class="kw">false</span> });
  }
});
  </pre>
</div>

<p>
  Look at that regex carefully. Specifically, look at the middle section:
  <code>(([-.]|[_]+)?([a-zA-Z0-9]+))*</code>. You have an outer group with <code>*</code>
  (repeat zero or more times), and inside it you have <code>[_]+</code> (one or more underscores)
  and <code>[a-zA-Z0-9]+</code> (one or more alphanumeric characters). That is a quantifier inside
  a quantifier -- a nested quantifier. This is the red flag. Whenever you see a pattern like
  <code>(a+)+</code>, <code>(a+)*</code>, or <code>(a|a)*</code>, you are looking at a potential
  ReDoS vulnerability.
</p>

<p>
  The code itself is perfectly ordinary. It takes an email from the request body, tests it against
  the regex, and returns whether it is valid. There is no injection here, no deserialization, no
  command execution. Just a regex test. And it is enough to take down the server.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> Understanding Catastrophic Backtracking</h2>

<p>
  To understand why nested quantifiers are dangerous, you need to understand how regex engines work.
  JavaScript uses a backtracking regex engine (technically, an NFA-based engine). When the engine
  tries to match a pattern against a string, it works left to right, consuming characters. When it
  reaches a point where the match fails, it does not just give up. It goes BACK to a previous
  decision point and tries a different path. This is called backtracking.
</p>

<p>
  For simple patterns, backtracking is fast. The engine might try a few alternatives and quickly
  determine whether the string matches. But with nested quantifiers, the number of alternative
  paths grows exponentially with the length of the input. Let me make this concrete.
</p>

<p>
  Consider the input <code>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!</code> -- that is 30 letter a's followed
  by an exclamation mark. The regex engine starts trying to match those a's against the nested groups
  <code>(([-.]|[_]+)?([a-zA-Z0-9]+))*</code>. The outer <code>*</code> means the engine can repeat
  the group any number of times. The inner <code>[a-zA-Z0-9]+</code> means each repetition can
  consume one or more characters. So the engine has to decide: how many characters does each
  repetition of the outer group consume?
</p>

<p>
  For 30 a's, the engine might try: all 30 in one group. Then 29 in the first group and 1 in the
  second. Then 28 and 2. Then 28, 1, and 1. Then 27, 2, and 1. You see where this is going. Each
  character can either be part of the current group repetition or the start of a new group
  repetition. For n characters, that is roughly 2^n possible ways to partition them among the
  groups. For 30 characters, that is 2^30 -- over one billion combinations. The engine tries
  every single one before concluding that the string does not match (because of the trailing
  exclamation mark that cannot satisfy the <code>@</code> requirement).
</p>

<p>
  Here is the scaling:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Backtracking growth</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// Input length vs approximate operations:</span>
<span class="cmt">// 15 a's + "!"  -->  2^15  =         32,768   (instant)</span>
<span class="cmt">// 20 a's + "!"  -->  2^20  =      1,048,576   (instant)</span>
<span class="cmt">// 25 a's + "!"  -->  2^25  =     33,554,432   (noticeable delay)</span>
<span class="cmt">// 30 a's + "!"  -->  2^30  =  1,073,741,824   (several seconds)</span>
<span class="cmt">// 35 a's + "!"  -->  2^35  = 34,359,738,368   (minutes)</span>
<span class="cmt">// 40 a's + "!"  -->  2^40  =  over a trillion  (process hangs)</span>
  </pre>
</div>

<p>
  This is not a CPU limit or a memory limit. It is an algorithmic explosion. The regex engine is
  doing exactly what it is designed to do -- exploring all possible matching paths. The problem is
  that the pattern creates an exponential number of paths. Double the input length and you square
  the computation time. This is the definition of catastrophic backtracking.
</p>

<div class="callout warn">
  <div class="callout-title">This Is Not Theoretical</div>
  <div class="callout-text">
    You can verify this yourself in a Node REPL. Run
    <code>console.time('regex'); /^([a-zA-Z0-9])(([-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}[a-z]{2,}\$/.test('a'.repeat(25) + '!'); console.timeEnd('regex');</code>
    and watch the delay grow as you increase the repeat count. Start with 20 and work your way up.
    Do NOT try 40 unless you want to kill the process.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> The Attack</h2>

<p>
  Now that you understand the mechanism, let us weaponize it. The attacker does not need to know
  your source code. They just need to guess (or discover through error messages) that your server
  validates email with a complex regex. They send a single request:
</p>

<div class="attack-box">
  <div class="attack-box-title">ReDoS Payload</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">curl request</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
curl -X POST http://localhost:3000/api/validate-email \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -d <span class="str">'{"email": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}'</span>
    </pre>
  </div>
</div>

<p>
  That is 40 a's followed by an exclamation mark. The server receives the request, passes the
  string to the regex engine, and the event loop locks up. The regex engine begins exploring
  over a trillion backtracking paths. Meanwhile, every other request to the server -- from every
  other user -- gets queued behind this regex evaluation. They all time out.
</p>

<p>
  Think about what just happened. The attacker did not need credentials. They did not need to find
  a SQL injection or steal a secret key. They sent one HTTP request with a 41-character string, and
  the entire server became unresponsive. This is a denial of service from a single request. No
  botnet required. No traffic amplification. Just one crafted input to an endpoint that runs a
  vulnerable regex.
</p>

<p>
  In a production scenario, this is even worse than it sounds. The server process is still alive --
  it is not crashed, so your process manager does not restart it. It is just stuck. Your health
  check endpoint is also blocked (it is on the same event loop), so your load balancer might not
  even know something is wrong until the health check timeout expires. The attacker can send these
  requests periodically to keep the server permanently locked up.
</p>

<div class="callout info">
  <div class="callout-title">Multiplied Impact</div>
  <div class="callout-text">
    If you are running a cluster of Node processes (using the cluster module or PM2), the attacker
    just needs to send one request per worker to take down the entire cluster. Four workers? Four
    requests. Eight workers? Eight requests. The attack scales trivially.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> The Fix -- Multiple Approaches</h2>

<p>
  There is no single silver bullet for ReDoS. You need a layered defense. Let me walk through each
  approach in order of importance.
</p>

<h3>Replace the Vulnerable Regex</h3>

<p>
  The most direct fix is to replace the complex regex with a simple one that does not have nested
  quantifiers. For email validation, you do not need to match the full RFC 5322 grammar. You need
  something that catches obvious typos and rejects garbage input. Here is a safe alternative:
</p>

<div class="fix-box">
  <div class="fix-box-title">Fixed: Safe Email Validation</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">routes/validate.js</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> router <span class="op">=</span> express.<span class="fn">Router</span>();

<span class="cmt">// SAFE: no nested quantifiers, linear-time matching</span>
<span class="kw">const</span> EMAIL_REGEX <span class="op">=</span> /^[^\\s@]+@[^\\s@]+\\.[^\\s@]{2,}\$/;

<span class="cmt">// Maximum email length per RFC 5321</span>
<span class="kw">const</span> MAX_EMAIL_LENGTH <span class="op">=</span> <span class="num">254</span>;

router.<span class="fn">post</span>(<span class="str">'/validate-email'</span>, (req, res) <span class="op">=></span> {
  <span class="kw">const</span> { email } <span class="op">=</span> req.body;

  <span class="cmt">// Length check BEFORE regex -- fast rejection, zero backtracking</span>
  <span class="kw">if</span> (!email || <span class="kw">typeof</span> email <span class="op">!==</span> <span class="str">'string'</span> || email.length <span class="op">></span> MAX_EMAIL_LENGTH) {
    <span class="kw">return</span> res.<span class="fn">json</span>({ valid: <span class="kw">false</span>, reason: <span class="str">'Invalid or too long'</span> });
  }

  <span class="kw">if</span> (EMAIL_REGEX.<span class="fn">test</span>(email)) {
    res.<span class="fn">json</span>({ valid: <span class="kw">true</span> });
  } <span class="kw">else</span> {
    res.<span class="fn">json</span>({ valid: <span class="kw">false</span> });
  }
});
    </pre>
  </div>
</div>

<p>
  The safe regex <code>/^[^\\s@]+@[^\\s@]+\\.[^\\s@]{2,}\$/</code> has no nested quantifiers.
  Each <code>[^\\s@]+</code> matches one or more non-whitespace, non-@ characters. There is only
  one way to match any given string against this pattern, so there is no backtracking explosion.
  The engine runs in linear time regardless of input length.
</p>

<h3>Input Length Limits</h3>

<p>
  Even before the regex runs, check the length of the input. A valid email address cannot exceed
  254 characters (per RFC 5321). If someone sends you a 10,000-character string as an email,
  reject it immediately. This is a trivial check -- one comparison -- and it eliminates the
  possibility of feeding long adversarial strings into any regex.
</p>

<h3>The Principle: Avoid Nested Quantifiers</h3>

<p>
  The general rule is this: if a quantified group contains another quantifier, the pattern is
  potentially vulnerable to catastrophic backtracking. These patterns are all dangerous:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Dangerous patterns</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// Nested quantifiers -- all potentially vulnerable</span>
(a+)+          <span class="cmt">// quantifier inside quantifier</span>
(a+)*          <span class="cmt">// quantifier inside quantifier</span>
(a|b)*a        <span class="cmt">// alternation inside quantifier with overlap</span>
(a|aa)+        <span class="cmt">// alternation inside quantifier with overlap</span>
(.*a){10}      <span class="cmt">// greedy .* inside a counted quantifier</span>
([a-zA-Z]+)*   <span class="cmt">// character class with + inside *</span>
  </pre>
</div>

<h3>Tooling: safe-regex and RE2</h3>

<p>
  You should not rely on manually reviewing every regex in your codebase. Use the
  <code>safe-regex</code> npm package to statically analyze patterns for potential backtracking
  vulnerabilities. You can integrate it into your CI pipeline to catch vulnerable patterns before
  they reach production.
</p>

<p>
  For a more fundamental fix, consider Google's RE2 regex engine, available in Node via the
  <code>re2</code> npm package. RE2 guarantees linear-time matching by construction. It does not
  use backtracking at all -- it uses a different algorithm (Thompson NFA) that processes each
  character exactly once. The tradeoff is that RE2 does not support backreferences or lookahead
  assertions, so some patterns cannot be expressed. But for validation and parsing tasks, RE2
  is an excellent choice that eliminates the entire class of ReDoS vulnerabilities.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Using RE2 in Node.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> RE2 <span class="op">=</span> <span class="fn">require</span>(<span class="str">'re2'</span>);

<span class="cmt">// RE2 guarantees linear-time matching -- no backtracking, ever</span>
<span class="kw">const</span> safePattern <span class="op">=</span> <span class="kw">new</span> <span class="fn">RE2</span>(<span class="str">/^[^\\s@]+@[^\\s@]+\\.[^\\s@]{2,}\$/</span>);

<span class="kw">if</span> (safePattern.<span class="fn">test</span>(email)) {
  <span class="cmt">// guaranteed to complete in O(n) time</span>
}
  </pre>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 6</span> Real-World ReDoS</h2>

<p>
  If you are thinking this is an obscure attack that only matters in CTF challenges, let me
  correct that impression with some real incidents.
</p>

<h3>ua-parser-js</h3>

<p>
  The <code>ua-parser-js</code> npm package is used to parse User-Agent strings from HTTP headers.
  It has millions of weekly downloads and is used by major companies. A regex in the package for
  parsing browser identifiers was found to be vulnerable to catastrophic backtracking. A crafted
  User-Agent header could lock up any server using this library. Think about that -- every incoming
  HTTP request typically includes a User-Agent header, and many servers parse it automatically via
  middleware. An attacker just needs to set their User-Agent to a malicious string.
</p>

<h3>validator.js</h3>

<p>
  The <code>validator.js</code> package had a ReDoS vulnerability in its email validation regex.
  Sound familiar? The exact same pattern we built in Step 2. Complex email validation regexes
  with nested quantifiers are a recurring source of ReDoS vulnerabilities because email addresses
  have a deceptively complex grammar that tempts developers into writing complex patterns.
</p>

<h3>Cloudflare Outage (2019)</h3>

<p>
  In July 2019, Cloudflare deployed a new rule to their Web Application Firewall. The rule
  contained a regex that exhibited catastrophic backtracking when applied to certain HTTP request
  bodies. Because the WAF runs inline on every request, the backtracking consumed all available
  CPU across Cloudflare's global network. The result: a significant portion of the internet became
  unreachable for approximately 30 minutes. Millions of websites behind Cloudflare returned errors.
  All because of one regex in one WAF rule.
</p>

<p>
  This is the lesson: ReDoS is not theoretical. It is not limited to toy applications. It has
  caused real outages at companies with world-class engineering teams. If Cloudflare can ship a
  vulnerable regex, so can you.
</p>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> Alternatives to Regex</h2>

<p>
  Sometimes the best regex is no regex at all. For several common use cases, there are better
  approaches that eliminate the ReDoS risk entirely.
</p>

<h3>Email Validation</h3>

<p>
  Here is a perspective that might surprise you: the best way to validate an email address is to
  send a confirmation email to it. No regex, no matter how complex, can tell you whether an email
  address actually works. It can only tell you whether the string looks plausible. For most
  applications, checking that the string contains an <code>@</code> symbol and at least one dot
  after it is sufficient. Then send a verification email. If it bounces, the address is invalid.
  If the user clicks the confirmation link, the address is valid. This approach is both more
  correct and more secure than any regex-based validation.
</p>

<h3>Complex Parsing</h3>

<p>
  If you are using regex to parse structured data -- URLs, HTML, CSV, configuration files -- you
  are almost certainly doing it wrong. Use a proper parser. The <code>url</code> module in Node
  parses URLs. Libraries like <code>cheerio</code> or <code>jsdom</code> parse HTML. CSV parsers
  handle edge cases that regex cannot. Parsers are designed for structured data. Regex is designed
  for pattern matching. Using regex as a parser invites both correctness bugs and performance
  vulnerabilities.
</p>

<h3>Worker Threads</h3>

<p>
  If you absolutely must run a complex regex and cannot simplify it, you can move the evaluation
  to a worker thread. Node's <code>worker_threads</code> module lets you run CPU-intensive
  operations off the main event loop. If the regex hangs, only the worker thread is blocked --
  the event loop continues handling other requests. You can also set a timeout on the worker
  and kill it if the regex takes too long.
</p>

<p>
  But I want to be clear: worker threads are a workaround, not a fix. The underlying vulnerability
  still exists. The regex still has catastrophic backtracking. You are just limiting the blast
  radius. The real fix is to eliminate the vulnerable pattern.
</p>

<div class="callout warn">
  <div class="callout-title">Audit Your Dependencies</div>
  <div class="callout-text">
    Your own code might be free of vulnerable regex patterns, but what about the packages you
    depend on? Libraries for validation, parsing, routing, and template rendering all use regular
    expressions internally. Run <code>npm audit</code> regularly and subscribe to security
    advisories for your critical dependencies. A ReDoS vulnerability in a transitive dependency
    can be just as devastating as one in your own code.
  </div>
</div>

<hr>

<h2>Lab 12 Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Build the POST /api/validate-email endpoint with the vulnerable nested-quantifier regex</li>
  <li><span class="task-check"></span> Test with increasing input lengths (20, 25, 30 a's + "!") and observe the exponential slowdown</li>
  <li><span class="task-check"></span> Explain why catastrophic backtracking occurs: nested quantifiers create 2^n possible match paths</li>
  <li><span class="task-check"></span> Replace the vulnerable regex with the safe pattern and add input length checks before regex evaluation</li>
  <li><span class="task-check"></span> Install safe-regex and scan your codebase for other vulnerable patterns</li>
  <li><span class="task-check"></span> Research the Cloudflare 2019 outage and understand how a single regex took down part of the internet</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="path">Previous: Path Traversal</button>
  <button class="nav-btn" data-next="cors">Next: CORS Misconfiguration</button>
</div>

`;
