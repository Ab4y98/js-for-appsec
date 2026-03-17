window.LESSONS = window.LESSONS || {};
window.LESSONS.csrf = `

<h1 class="lesson-title">Lab 06: Cross-Site Request Forgery</h1>

<p class="lesson-subtitle">
  The attack where the victim's own browser becomes the weapon. You will build a vulnerable endpoint, craft an
  attack page that silently submits requests on behalf of a logged-in user, and then implement the defenses
  that make it impossible. This one is subtle, and it is one of the most commonly misunderstood vulnerabilities
  in web security.
</p>

<hr>

<h2>Why CSRF Matters</h2>

<p>
  I want to start with a story. A few years ago, I was auditing a mid-size SaaS application. Their authentication
  was solid -- bcrypt, secure sessions, the works. But their profile update endpoint had no CSRF protection. I built
  a proof-of-concept page in about ten minutes, hosted it on a throwaway domain, and sent the link to the dev team
  lead in a Slack message. He clicked it. His display name changed to "CSRF is real" and his email updated to one
  I controlled. From there, I could have triggered a password reset and taken over his account entirely. The whole
  thing took less time than writing this paragraph.
</p>

<p>
  The fundamental problem with CSRF is deceptively simple: when your browser makes a request to a website, it
  automatically attaches all cookies for that domain. Every single time. It does not care where the request
  originated. It does not care if you clicked a button on the legitimate site or if a hidden form on some sketchy
  page triggered the request. Cookies go along for the ride, and the server on the other end has no way to tell
  the difference. That is the entire attack in one paragraph, and everything else in this lab is just
  exploring the implications.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> Build the Vulnerable Endpoint</h2>

<p>
  Let us start by building a profile update route that is completely vulnerable to CSRF. This is not contrived
  code. This is what profile update endpoints actually look like in applications where nobody has thought about
  CSRF yet. The route checks that you are logged in -- it verifies <code>req.session?.user</code> -- and then
  processes the update. That sounds secure, right? You have to be authenticated. The problem is that authentication
  alone is not enough. The server knows <em>who</em> is making the request, but it has no idea <em>where</em>
  the request came from.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/profile.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> express = <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> router = express.<span class="fn">Router</span>();

<span class="cmt">// Vulnerable: no CSRF token validation</span>
router.<span class="fn">post</span>(<span class="str">'/api/profile/update'</span>, (<span class="fn">req</span>, <span class="fn">res</span>) <span class="op">=></span> {
  <span class="kw">if</span> (!req.session?.user) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Not authenticated'</span> });
  }

  <span class="kw">const</span> { displayName, email } = req.body;

  <span class="cmt">// Update the user profile in the database</span>
  db.<span class="fn">run</span>(
    <span class="str">'UPDATE users SET display_name = ?, email = ? WHERE id = ?'</span>,
    [displayName, email, req.session.user.id],
    (<span class="fn">err</span>) <span class="op">=></span> {
      <span class="kw">if</span> (err) <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">500</span>).<span class="fn">json</span>({ error: <span class="str">'Update failed'</span> });
      res.<span class="fn">json</span>({ success: <span class="kw">true</span>, message: <span class="str">'Profile updated'</span> });
    }
  );
});

module.exports = router;
  </pre>
</div>

<p>
  And here is the legitimate form that goes with it. This is what your users see on the settings page.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">views/profile.ejs</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="op">&lt;</span>form <span class="fn">action</span>=<span class="str">"/api/profile/update"</span> <span class="fn">method</span>=<span class="str">"POST"</span><span class="op">&gt;</span>
  <span class="op">&lt;</span>label<span class="op">&gt;</span>Display Name<span class="op">&lt;</span>/label<span class="op">&gt;</span>
  <span class="op">&lt;</span>input <span class="fn">type</span>=<span class="str">"text"</span> <span class="fn">name</span>=<span class="str">"displayName"</span>
    <span class="fn">value</span>=<span class="str">"&lt;%= user.display_name %&gt;"</span><span class="op">&gt;</span>

  <span class="op">&lt;</span>label<span class="op">&gt;</span>Email<span class="op">&lt;</span>/label<span class="op">&gt;</span>
  <span class="op">&lt;</span>input <span class="fn">type</span>=<span class="str">"email"</span> <span class="fn">name</span>=<span class="str">"email"</span>
    <span class="fn">value</span>=<span class="str">"&lt;%= user.email %&gt;"</span><span class="op">&gt;</span>

  <span class="cmt">&lt;!-- No CSRF token field. That is the problem. --&gt;</span>
  <span class="op">&lt;</span>button <span class="fn">type</span>=<span class="str">"submit"</span><span class="op">&gt;</span>Save Changes<span class="op">&lt;</span>/button<span class="op">&gt;</span>
<span class="op">&lt;</span>/form<span class="op">&gt;</span>
  </pre>
</div>

<p>
  Look at this code carefully. There is authentication. There is a session check. The query is even parameterized
  to prevent SQL injection. A lot of things are done right. But there is one glaring omission: nothing in this
  flow proves that the request originated from your actual form. Any page, anywhere on the internet, can submit
  a POST request to <code>/api/profile/update</code>, and as long as the victim's browser sends along the session
  cookie, the server will happily process it.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Craft the Attack</h2>

<p>
  Now let us switch hats. You are the attacker. You know that the target application has a profile update endpoint
  with no CSRF protection. You do not need the victim's password. You do not need to break into the server. You
  just need them to visit a page you control while they are logged in. That is it.
</p>

<div class="attack-box">
  <div class="attack-box-title">The Attack Page</div>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">attacker-site/index.html</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="op">&lt;</span>!DOCTYPE html<span class="op">&gt;</span>
<span class="op">&lt;</span>html<span class="op">&gt;</span>
<span class="op">&lt;</span>head<span class="op">&gt;</span><span class="op">&lt;</span>title<span class="op">&gt;</span>Win a Free iPhone!<span class="op">&lt;</span>/title<span class="op">&gt;</span><span class="op">&lt;</span>/head<span class="op">&gt;</span>
<span class="op">&lt;</span>body<span class="op">&gt;</span>
  <span class="op">&lt;</span>h1<span class="op">&gt;</span>Congratulations! Click below to claim your prize!<span class="op">&lt;</span>/h1<span class="op">&gt;</span>

  <span class="cmt">&lt;!-- Hidden form that auto-submits --&gt;</span>
  <span class="op">&lt;</span>form
    <span class="fn">id</span>=<span class="str">"csrf-form"</span>
    <span class="fn">action</span>=<span class="str">"http://localhost:3000/api/profile/update"</span>
    <span class="fn">method</span>=<span class="str">"POST"</span>
    <span class="fn">style</span>=<span class="str">"display:none"</span><span class="op">&gt;</span>

    <span class="op">&lt;</span>input <span class="fn">type</span>=<span class="str">"hidden"</span> <span class="fn">name</span>=<span class="str">"displayName"</span>
      <span class="fn">value</span>=<span class="str">"Hacked by CSRF"</span><span class="op">&gt;</span>
    <span class="op">&lt;</span>input <span class="fn">type</span>=<span class="str">"hidden"</span> <span class="fn">name</span>=<span class="str">"email"</span>
      <span class="fn">value</span>=<span class="str">"attacker@evil.com"</span><span class="op">&gt;</span>
  <span class="op">&lt;</span>/form<span class="op">&gt;</span>

  <span class="op">&lt;</span>script<span class="op">&gt;</span>
    document.<span class="fn">getElementById</span>(<span class="str">'csrf-form'</span>).<span class="fn">submit</span>();
  <span class="op">&lt;</span>/script<span class="op">&gt;</span>
<span class="op">&lt;</span>/body<span class="op">&gt;</span>
<span class="op">&lt;</span>/html<span class="op">&gt;</span>
    </pre>
  </div>
</div>

<p>
  Here is the attack flow, step by step. The victim is logged into your application at <code>localhost:3000</code>.
  Their session cookie is sitting in their browser. They receive a link -- maybe in an email, maybe in a chat
  message, maybe in a forum post -- and they click it. The link takes them to the attacker's page. The page loads,
  and the hidden form immediately auto-submits via JavaScript. The browser sends a POST request to
  <code>localhost:3000/api/profile/update</code>, and because the request is going to <code>localhost:3000</code>,
  the browser attaches the session cookie automatically. The server receives the request, sees a valid session,
  and processes the profile update. The victim's display name is now "Hacked by CSRF" and their email is
  <code>attacker@evil.com</code>.
</p>

<p>
  And here is the part that really matters: if you look at the server logs, this request looks completely
  normal. There is nothing suspicious about it. It is a POST request to a valid endpoint with a valid session
  cookie. The HTTP headers will show the <code>Referer</code> as the attacker's domain, but how many applications
  actually check the Referer header on every request? Almost none. The server has no mechanism to distinguish
  this forged request from a legitimate one.
</p>

<div class="callout warn">
  <div class="callout-title">Why This Is Dangerous</div>
  <div class="callout-text">
    Notice that the attacker never steals the session cookie. They do not need to. They do not even need to
    see the response. CSRF is a one-way attack: the attacker triggers an action, and the victim's browser
    does the rest. The same-origin policy prevents the attacker from reading the response, but they do not
    care about the response. The damage is the side effect -- the profile update, the password change, the
    bank transfer.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> JSON Content-Type CSRF</h2>

<p>
  Here is where a lot of developers get a false sense of security. "Our API only accepts JSON," they say.
  "CORS will block cross-origin requests." And they are partly right -- but partly right in security is
  the same as wrong.
</p>

<p>
  Let me explain how CORS and content types interact. When a browser makes a cross-origin request, it checks
  whether a CORS preflight is required. A preflight is an OPTIONS request that asks the server, "Hey, is this
  cross-origin request allowed?" But here is the critical detail: not all requests trigger a preflight. Requests
  that meet certain criteria are classified as "simple requests" and go straight through without a preflight.
  A simple request uses GET, HEAD, or POST with one of these content types:
  <code>application/x-www-form-urlencoded</code>, <code>multipart/form-data</code>, or <code>text/plain</code>.
</p>

<p>
  So if your server accepts <code>application/x-www-form-urlencoded</code> -- and Express with
  <code>express.urlencoded()</code> middleware does by default -- then a cross-origin form submission goes
  through without any preflight. CORS never even enters the picture for standard form POSTs.
</p>

<p>
  But what about APIs that strictly require <code>application/json</code>? An attacker cannot set the
  Content-Type to <code>application/json</code> from a regular HTML form. That would trigger a preflight.
  However, there are tricks. An attacker can use <code>enctype="text/plain"</code> on a form and structure
  the input name/value pairs so the resulting body is valid JSON:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">attacker-site/json-csrf.html</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">&lt;!-- Trick: form sends text/plain, but body looks like JSON --&gt;</span>
<span class="op">&lt;</span>form
  <span class="fn">action</span>=<span class="str">"http://localhost:3000/api/profile/update"</span>
  <span class="fn">method</span>=<span class="str">"POST"</span>
  <span class="fn">enctype</span>=<span class="str">"text/plain"</span><span class="op">&gt;</span>

  <span class="op">&lt;</span>input <span class="fn">type</span>=<span class="str">"hidden"</span>
    <span class="fn">name</span>=<span class="str">'{"displayName":"Hacked","email":"attacker@evil.com","ignore":"'</span>
    <span class="fn">value</span>=<span class="str">'whatever"}'</span><span class="op">&gt;</span>
<span class="op">&lt;</span>/form<span class="op">&gt;</span>
  </pre>
</div>

<p>
  The resulting request body ends up looking like:
  <code>{"displayName":"Hacked","email":"attacker@evil.com","ignore":"=whatever"}</code>.
  If the server parses this as JSON (some configurations will), the attack succeeds. This does not work against
  every setup, but it works against enough of them that you cannot rely on content-type checking alone.
</p>

<h3>SameSite=Lax Edge Cases</h3>

<p>
  Modern browsers default cookies to <code>SameSite=Lax</code>, which blocks cookies on cross-site POST
  requests. This is a huge improvement. But Lax has an important exception: it allows cookies on top-level
  GET navigations from cross-origin sites. That means if your application has any state-changing GET endpoints
  (and you would be surprised how many do), they are still vulnerable even with Lax cookies. A simple
  <code>&lt;a href="http://yourapp.com/api/delete-account?confirm=true"&gt;</code> on an attacker's page
  can trigger the action if the user clicks it, because the browser treats a top-level link click as a
  safe navigation and sends the cookies along.
</p>

<div class="callout info">
  <div class="callout-title">The SameSite Timeline</div>
  <div class="callout-text">
    Chrome started defaulting to <code>SameSite=Lax</code> in 2020. Firefox and Safari followed. This default
    dramatically reduced the attack surface for CSRF, but it did not eliminate it. You still need explicit
    CSRF tokens for POST requests, and you absolutely must not put state-changing logic behind GET endpoints.
    Lax is a safety net, not a solution.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> The Fix -- Tokens + SameSite Cookies</h2>

<p>
  The standard defense against CSRF is the synchronizer token pattern, and it is beautifully simple. The idea
  is this: when the server renders a form, it generates a random, unpredictable token and embeds it as a hidden
  field. When the form is submitted, the server checks that the token in the request matches the one it generated.
  An attacker on a different origin cannot read the token (the same-origin policy prevents that), so they cannot
  include it in their forged request. Without the correct token, the server rejects the submission.
</p>

<div class="fix-box">
  <div class="fix-box-title">Implementing CSRF Protection</div>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">app.js -- CSRF middleware setup</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="kw">const</span> csrf = <span class="fn">require</span>(<span class="str">'csurf'</span>);
<span class="kw">const</span> cookieParser = <span class="fn">require</span>(<span class="str">'cookie-parser'</span>);

app.<span class="fn">use</span>(<span class="fn">cookieParser</span>());

<span class="cmt">// Initialize CSRF protection</span>
<span class="kw">const</span> csrfProtection = <span class="fn">csrf</span>({ cookie: <span class="kw">false</span> }); <span class="cmt">// Use session-based tokens</span>

<span class="cmt">// Apply to all state-changing routes</span>
app.<span class="fn">use</span>(csrfProtection);

<span class="cmt">// Make the token available to all templates</span>
app.<span class="fn">use</span>((<span class="fn">req</span>, <span class="fn">res</span>, <span class="fn">next</span>) <span class="op">=></span> {
  res.locals.csrfToken = req.<span class="fn">csrfToken</span>();
  <span class="fn">next</span>();
});
    </pre>
  </div>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">views/profile.ejs -- Fixed form</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="op">&lt;</span>form <span class="fn">action</span>=<span class="str">"/api/profile/update"</span> <span class="fn">method</span>=<span class="str">"POST"</span><span class="op">&gt;</span>
  <span class="cmt">&lt;!-- CSRF token embedded as hidden field --&gt;</span>
  <span class="op">&lt;</span>input <span class="fn">type</span>=<span class="str">"hidden"</span> <span class="fn">name</span>=<span class="str">"_csrf"</span>
    <span class="fn">value</span>=<span class="str">"&lt;%= csrfToken %&gt;"</span><span class="op">&gt;</span>

  <span class="op">&lt;</span>label<span class="op">&gt;</span>Display Name<span class="op">&lt;</span>/label<span class="op">&gt;</span>
  <span class="op">&lt;</span>input <span class="fn">type</span>=<span class="str">"text"</span> <span class="fn">name</span>=<span class="str">"displayName"</span>
    <span class="fn">value</span>=<span class="str">"&lt;%= user.display_name %&gt;"</span><span class="op">&gt;</span>

  <span class="op">&lt;</span>label<span class="op">&gt;</span>Email<span class="op">&lt;</span>/label<span class="op">&gt;</span>
  <span class="op">&lt;</span>input <span class="fn">type</span>=<span class="str">"email"</span> <span class="fn">name</span>=<span class="str">"email"</span>
    <span class="fn">value</span>=<span class="str">"&lt;%= user.email %&gt;"</span><span class="op">&gt;</span>

  <span class="op">&lt;</span>button <span class="fn">type</span>=<span class="str">"submit"</span><span class="op">&gt;</span>Save Changes<span class="op">&lt;</span>/button<span class="op">&gt;</span>
<span class="op">&lt;</span>/form<span class="op">&gt;</span>
    </pre>
  </div>
</div>

<p>
  Now let us also harden the session cookie itself. The <code>SameSite</code> attribute tells the browser
  when to send cookies on cross-origin requests. You have three options:
</p>

<p>
  <strong>SameSite=Strict:</strong> The cookie is never sent on cross-origin requests. Not on form submissions,
  not on link clicks, not on anything. This is the most secure setting, but it means that if someone follows a
  link to your site from an external page, they will not be logged in on that first request. The user experience
  trade-off is real, which is why many applications use Lax instead.
</p>

<p>
  <strong>SameSite=Lax:</strong> The cookie is sent on top-level GET navigations (clicking a link) but not on
  cross-origin POST submissions, iframes, or AJAX requests. This is the browser default and stops most CSRF
  attacks while preserving a reasonable user experience.
</p>

<p>
  <strong>SameSite=None:</strong> The cookie is always sent, even on cross-origin requests. This requires the
  <code>Secure</code> flag (HTTPS only). You need this for legitimate cross-origin scenarios like embedded
  iframes, but it offers zero CSRF protection.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">app.js -- Hardened session configuration</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
app.<span class="fn">use</span>(<span class="fn">session</span>({
  secret: process.env.SESSION_SECRET,
  resave: <span class="kw">false</span>,
  saveUninitialized: <span class="kw">false</span>,
  cookie: {
    httpOnly: <span class="kw">true</span>,      <span class="cmt">// JS cannot access the cookie</span>
    secure: <span class="kw">true</span>,        <span class="cmt">// HTTPS only</span>
    sameSite: <span class="str">'strict'</span>, <span class="cmt">// Never sent cross-origin</span>
    maxAge: <span class="num">1800000</span>      <span class="cmt">// 30 minutes</span>
  }
}));
  </pre>
</div>

<h3>Double-Submit Cookie Pattern</h3>

<p>
  There is an alternative CSRF defense that does not require server-side state: the double-submit cookie
  pattern. The idea is that you set a random token in a cookie and also include that same token in a hidden
  form field or custom header. On submission, the server compares the two values. An attacker can trigger the
  browser to send the cookie, but they cannot read its value (same-origin policy), so they cannot include the
  matching token in the form field. This pattern is particularly useful for stateless architectures and SPAs
  where you do not have server-side sessions to store synchronizer tokens.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> CORS and CSRF Interaction</h2>

<p>
  I see a lot of confusion about the relationship between CORS and CSRF, so let me be precise about what
  CORS actually does and does not do.
</p>

<p>
  CORS preflight protects you only when the request is "non-simple." A non-simple request is one that uses
  a method other than GET, HEAD, or POST, or sets custom headers (like <code>X-Requested-With</code>), or
  uses a content type other than the three simple types (<code>application/x-www-form-urlencoded</code>,
  <code>multipart/form-data</code>, <code>text/plain</code>). For non-simple requests, the browser sends
  an OPTIONS preflight first, and if the server does not explicitly allow the requesting origin, the browser
  blocks the request. That is real protection.
</p>

<p>
  But a standard HTML form submission -- which is the classic CSRF vector -- is a simple request. No preflight.
  The browser sends it directly. CORS does not even look at it. This is why the old trick of requiring an
  <code>X-Requested-With: XMLHttpRequest</code> header used to work as a CSRF defense: that custom header
  makes the request non-simple, which triggers a preflight, which fails for cross-origin requests unless the
  server explicitly allows it. Many older frameworks like Rails and Django set this header automatically on
  AJAX calls. It works, but it only protects AJAX endpoints. Traditional form submissions bypass it entirely.
</p>

<p>
  The bottom line: CORS is an access control mechanism for cross-origin reads, not a CSRF defense. It can
  incidentally prevent some CSRF scenarios (specifically those involving non-simple requests), but relying on
  it as your primary CSRF defense is a mistake. Use tokens. Use SameSite cookies. Use both.
</p>

<div class="callout warn">
  <div class="callout-title">Do Not Rely on CORS Alone</div>
  <div class="callout-text">
    If your CSRF defense strategy is "we have CORS configured," you almost certainly have vulnerable endpoints.
    Any endpoint that accepts form-encoded data or text/plain will be reachable from cross-origin forms without
    a preflight. CORS protects reads, not writes. You need explicit anti-CSRF mechanisms for anything that
    changes state.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> Login CSRF</h2>

<p>
  Here is a variant that most developers never think about, and it is one of my favorites to demonstrate
  in security training because it completely inverts expectations. In a normal CSRF attack, the attacker
  forces the victim to perform an action in the victim's own account. In login CSRF, the attacker forces
  the victim to log into the <em>attacker's</em> account.
</p>

<p>
  Think about what that means. The victim visits the attacker's page, which contains a hidden form that
  submits a login request to your application using the attacker's credentials. The victim's browser logs
  them in as the attacker. Now the victim is using your application, thinking it is their own account, but
  everything they do is happening inside the attacker's account. If the victim enters a credit card, the
  attacker can see it in their account settings. If the victim uploads sensitive documents, they go into the
  attacker's storage. If the victim saves a home address, the attacker gets it.
</p>

<p>
  This attack is particularly dangerous because the victim has no obvious reason to be suspicious. The
  application works normally. They can navigate, enter data, and use features. They just happen to be in
  the wrong account. Most users will not notice, especially on mobile where the UI real estate is limited.
</p>

<p>
  The fix is straightforward: protect your login endpoint with a CSRF token, just like every other
  state-changing endpoint. I know it seems odd to put CSRF protection on a form that does not require
  authentication, but the attack vector is real and well-documented. Every modern web framework's CSRF
  documentation explicitly calls out login forms as needing protection.
</p>

<div class="callout info">
  <div class="callout-title">Login CSRF in the Wild</div>
  <div class="callout-text">
    Google, Facebook, and PayPal have all had login CSRF vulnerabilities reported through their bug bounty
    programs. It is a real attack class that affects real applications. If your login form does not have a
    CSRF token, add one today. It takes five minutes and closes a vulnerability that most scanners will not
    even flag.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> Image Tag CSRF (GET-Based State Changes)</h2>

<p>
  Here is another variant that catches developers off guard. If your application performs state-changing
  operations via GET requests -- deleting a resource, toggling a setting, confirming an action -- an attacker
  does not even need a form. They just need an image tag.
</p>

<div class="attack-box">
  <div class="attack-box-title">Attack: CSRF via Image Tag</div>
  <pre>
<span class="cmt">&lt;!-- The victim's browser loads this "image" --&gt;</span>
<span class="cmt">&lt;!-- The GET request fires automatically with cookies --&gt;</span>

&lt;img src="http://localhost:3000/api/account/delete?confirm=true"
     style="display:none"
     onerror="this.style.display='none'" /&gt;

<span class="cmt">&lt;!-- Multiple actions in one page --&gt;</span>
&lt;img src="http://localhost:3000/api/settings/notifications?enabled=false" /&gt;
&lt;img src="http://localhost:3000/api/notes/1?action=delete" /&gt;
  </pre>
</div>

<p>
  The browser does not know the difference between loading an image and triggering an API call. It just
  makes the GET request and attaches cookies. The response is not a valid image, so the browser quietly
  discards it, but the server already processed the request. The victim never sees anything unusual.
</p>

<p>
  This is why the HTTP specification says GET requests must be safe and idempotent -- they must not
  change server state. If your application uses GET for state changes, it is vulnerable to the simplest
  possible CSRF attack: one line of HTML. The fix is architectural: never use GET for operations that
  modify data. Use POST, PUT, PATCH, or DELETE, and protect those with CSRF tokens.
</p>

<div class="callout warn">
  <div class="callout-title">GET Must Be Safe</div>
  <div class="callout-text">
    If any of your GET endpoints change state -- delete records, toggle settings, transfer funds,
    confirm actions -- you have a CSRF vulnerability that is trivially exploitable with a single
    image tag. Audit every GET route in your application. If it modifies data, change it to POST
    and add CSRF protection.
  </div>
</div>

<hr>

<h2>Task Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Build the vulnerable profile update endpoint with session auth but no CSRF token</li>
  <li><span class="task-check"></span> Create an attacker page with a hidden auto-submitting form that changes the victim's profile</li>
  <li><span class="task-check"></span> Test the attack: log in, visit the attacker page in another tab, verify the profile was changed</li>
  <li><span class="task-check"></span> Exploit a GET-based state-changing endpoint using an image tag and confirm the action executes</li>
  <li><span class="task-check"></span> Implement csurf middleware and add the CSRF token hidden field to the profile form</li>
  <li><span class="task-check"></span> Configure session cookies with SameSite=Strict, httpOnly, and secure flags</li>
  <li><span class="task-check"></span> Add CSRF protection to the login form and verify that login CSRF is no longer possible</li>
  <li><span class="task-check"></span> Audit all GET endpoints and move any state-changing operations to POST/PUT/DELETE methods</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="nosql">Back: NoSQL Injection</button>
  <button class="nav-btn" data-next="jwt">Next: JWT Attacks</button>
</div>

`;
