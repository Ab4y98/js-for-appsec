window.LESSONS = window.LESSONS || {};
window.LESSONS.sqli = `

<div class="lesson-title">SQL Injection</div>
<div class="lesson-subtitle">
  Lab 02 — The vulnerability that has been destroying applications since the late 1990s.
  You are going to build it, exploit it three different ways, and then fix it for good.
</div>

<!-- ════════════════════════════════════════════ -->
<!-- STEP 1: Build the Vulnerable Route          -->
<!-- ════════════════════════════════════════════ -->
<div class="step">
  <div class="step-label">Step 1</div>
  <h3>Build the Vulnerable Route</h3>

  <p>
    Let's start by building a login endpoint the way you will encounter it in legacy codebases.
    I have personally seen this exact pattern in production applications serving real customers.
    The code works — it logs people in, it checks passwords — and it is catastrophically broken.
  </p>

  <p>
    The core mistake is building a SQL query by gluing strings together.
    When you use template literals or string concatenation to drop user input straight into a SQL
    statement, the database has absolutely no way to tell which part is your query logic and which
    part came from the user. It is all just one big string of text. That is the entire vulnerability
    in a single sentence.
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">routes/login.js</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span><span class="op">(</span><span class="str">'express'</span><span class="op">);</span>
<span class="kw">const</span> router  <span class="op">=</span> express.<span class="fn">Router</span><span class="op">();</span>
<span class="kw">const</span> db      <span class="op">=</span> <span class="fn">require</span><span class="op">(</span><span class="str">'../db'</span><span class="op">);</span>

<span class="cmt">// GET  — render the login form</span>
router.<span class="fn">get</span><span class="op">(</span><span class="str">'/login'</span><span class="op">,</span> <span class="op">(</span>req<span class="op">,</span> res<span class="op">)</span> <span class="kw">=&gt;</span> <span class="op">{</span>
  res.<span class="fn">render</span><span class="op">(</span><span class="str">'login'</span><span class="op">);</span>
<span class="op">});</span>

<span class="cmt">// POST — handle login (VULNERABLE)</span>
router.<span class="fn">post</span><span class="op">(</span><span class="str">'/login'</span><span class="op">,</span> <span class="op">(</span>req<span class="op">,</span> res<span class="op">)</span> <span class="kw">=&gt;</span> <span class="op">{</span>
  <span class="kw">const</span> <span class="op">{</span> username<span class="op">,</span> password <span class="op">}</span> <span class="op">=</span> req<span class="op">.</span>body<span class="op">;</span>

  <span class="cmt">// DANGER: string interpolation builds ONE string</span>
  <span class="kw">const</span> query <span class="op">=</span> <span class="str">\`SELECT * FROM users
    WHERE username = '\${username}'
    AND password = '\${password}'\`</span><span class="op">;</span>

  <span class="kw">const</span> user <span class="op">=</span> db.<span class="fn">prepare</span><span class="op">(</span>query<span class="op">).</span><span class="fn">get</span><span class="op">();</span>

  <span class="kw">if</span> <span class="op">(</span>user<span class="op">)</span> <span class="op">{</span>
    req<span class="op">.</span>session<span class="op">.</span>user <span class="op">=</span> user<span class="op">;</span>
    res.<span class="fn">redirect</span><span class="op">(</span><span class="str">'/dashboard'</span><span class="op">);</span>
  <span class="op">}</span> <span class="kw">else</span> <span class="op">{</span>
    res.<span class="fn">render</span><span class="op">(</span><span class="str">'login'</span><span class="op">,</span> <span class="op">{</span> error<span class="op">:</span> <span class="str">'Invalid credentials'</span> <span class="op">});</span>
  <span class="op">}</span>
<span class="op">});</span>

module<span class="op">.</span>exports <span class="op">=</span> router<span class="op">;</span></code></pre>
  </div>

  <p>
    And here is the simple EJS form that sends the POST request:
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">views/login.ejs</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><span class="op">&lt;</span>form method<span class="op">=</span><span class="str">"POST"</span> action<span class="op">=</span><span class="str">"/login"</span><span class="op">&gt;</span>
  <span class="op">&lt;</span>input name<span class="op">=</span><span class="str">"username"</span> placeholder<span class="op">=</span><span class="str">"Username"</span> <span class="op">/&gt;</span>
  <span class="op">&lt;</span>input name<span class="op">=</span><span class="str">"password"</span> type<span class="op">=</span><span class="str">"password"</span> placeholder<span class="op">=</span><span class="str">"Password"</span> <span class="op">/&gt;</span>
  <span class="op">&lt;</span>button type<span class="op">=</span><span class="str">"submit"</span><span class="op">&gt;</span>Log In<span class="op">&lt;/</span>button<span class="op">&gt;</span>
<span class="op">&lt;/</span>form<span class="op">&gt;</span></code></pre>
  </div>

  <div class="callout warn">
    <div class="callout-title">Why this is dangerous</div>
    <div class="callout-text">
      The database receives a single string. It parses that string as SQL.
      If the attacker's input contains SQL syntax, the database will execute it.
      There is no firewall, no validation layer, no magic boundary between
      "your SQL" and "their SQL." It is all one query.
    </div>
  </div>
</div>

<!-- ════════════════════════════════════════════ -->
<!-- STEP 2: Authentication Bypass               -->
<!-- ════════════════════════════════════════════ -->
<div class="step">
  <div class="step-label">Step 2</div>
  <h3>Authentication Bypass</h3>

  <p>
    Now let's break it. The classic payload for authentication bypass is:
  </p>

  <div class="attack-box">
    <div class="attack-box-title">Attack Payload</div>
    <code>' OR '1'='1' --</code>
    <p style="margin-top:12px;">
      Enter this as the <strong>username</strong>. The password field can be anything.
    </p>
  </div>

  <p>
    Let's walk through this character by character. When the server substitutes the payload into
    the query template, the database sees this:
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">What the database actually executes</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><span class="kw">SELECT</span> <span class="op">*</span> <span class="kw">FROM</span> users
<span class="kw">WHERE</span> username <span class="op">=</span> <span class="str">''</span> <span class="kw">OR</span> <span class="str">'1'</span><span class="op">=</span><span class="str">'1'</span> <span class="cmt">-- ' AND password = 'whatever'</span></code></pre>
  </div>

  <p>
    Here is what happened, piece by piece:
  </p>

  <ul>
    <li>
      The first <code>'</code> in the payload closes the opening quote around the username value.
      The username is now an empty string.
    </li>
    <li>
      <code>OR '1'='1'</code> adds a condition that is always true. The WHERE clause now
      matches every single row in the users table.
    </li>
    <li>
      <code>--</code> is the SQL comment marker. Everything after it is ignored by the database.
      This chops off the rest of your original query — the <code>AND password = '...'</code> part
      simply disappears.
    </li>
  </ul>

  <p>
    The result: the database returns the first user in the table. In most applications, that is the
    admin account. You just logged in as admin without knowing the password.
  </p>

  <p>
    Test it with curl:
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Terminal</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code>curl -X POST http://localhost:3000/login \\
  -H <span class="str">"Content-Type: application/x-www-form-urlencoded"</span> \\
  -d <span class="str">"username=' OR '1'='1' --&amp;password=anything"</span> \\
  -v</code></pre>
  </div>

  <p>
    You should see a <code>302 redirect</code> to <code>/dashboard</code> — that means the
    application accepted the login. You are now authenticated as the first user in the database.
  </p>

  <div class="callout info">
    <div class="callout-title">The comment trick</div>
    <div class="callout-text">
      The <code>--</code> comment is essential. Without it, the leftover <code>'</code> from
      the original query would cause a syntax error and the injection would fail. The comment
      cleanly removes the tail of the query. Some databases use <code>#</code> instead of
      <code>--</code> for comments. MySQL accepts both.
    </div>
  </div>
</div>

<!-- ════════════════════════════════════════════ -->
<!-- STEP 3: Data Exfiltration with UNION        -->
<!-- ════════════════════════════════════════════ -->
<div class="step">
  <div class="step-label">Step 3</div>
  <h3>Data Exfiltration with UNION SELECT</h3>

  <p>
    Authentication bypass is bad. But the real nightmare is when the attacker starts
    extracting data from your database. This is where UNION SELECT comes in.
  </p>

  <p>
    A UNION in SQL appends the results of a second SELECT statement to the first one.
    The catch: both SELECT statements must return the same number of columns. So the
    attacker's first job is figuring out how many columns the original query returns.
  </p>

  <h4>Determining the column count</h4>

  <p>
    The ORDER BY trick is the standard approach. You keep incrementing the column index
    until the database throws an error:
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Probing column count</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><span class="cmt">-- No error: table has at least 1 column</span>
<span class="str">' ORDER BY 1 --</span>

<span class="cmt">-- No error: at least 2 columns</span>
<span class="str">' ORDER BY 2 --</span>

<span class="cmt">-- No error: at least 3 columns</span>
<span class="str">' ORDER BY 3 --</span>

<span class="cmt">-- ERROR: column 6 does not exist → table has 5 columns</span>
<span class="str">' ORDER BY 6 --</span></code></pre>
  </div>

  <p>
    Once you know the column count, you can craft a UNION SELECT that pulls data from
    any table in the database. Our users table has 5 columns: id, username, password, role, email.
  </p>

  <div class="attack-box">
    <div class="attack-box-title">UNION SELECT Payload</div>
    <code>' UNION SELECT id, username, password, role, email FROM users --</code>
  </div>

  <p>
    When the application runs this, the database executes the original query (which returns
    nothing because the username is empty), then appends every row from the users table.
    If the application displays the returned user object anywhere — in a profile page,
    in a JSON response, even in an error message — the attacker now has every username,
    password, role, and email in your database.
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Terminal</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code>curl -X POST http://localhost:3000/login \\
  -H <span class="str">"Content-Type: application/x-www-form-urlencoded"</span> \\
  -d <span class="str">"username=' UNION SELECT id, username, password, role, email FROM users --&amp;password=x"</span> \\
  -v</code></pre>
  </div>

  <div class="callout warn">
    <div class="callout-title">This is a full database dump</div>
    <div class="callout-text">
      In a real attack, the target is not just the users table. The attacker can query
      <code>sqlite_master</code> (SQLite), <code>information_schema.tables</code> (MySQL/Postgres),
      or <code>sys.tables</code> (SQL Server) to discover every table in your database, then
      extract them one by one.
    </div>
  </div>
</div>

<!-- ════════════════════════════════════════════ -->
<!-- STEP 4: Error-Based and Blind Injection     -->
<!-- ════════════════════════════════════════════ -->
<div class="step">
  <div class="step-label">Step 4</div>
  <h3>Error-Based and Blind Injection</h3>

  <p>
    What happens when the application does not display query results to the user? Maybe
    the login page just shows "Invalid credentials" regardless of the query output. Does
    that stop the attacker? Not even close.
  </p>

  <h4>Error-Based Extraction</h4>

  <p>
    If the application displays database error messages (which many do in development, and
    some accidentally do in production), the attacker can force the database to embed data
    inside an error message. For example, in SQLite:
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Error-based payload (SQLite)</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><span class="str">' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INTEGER) --</span></code></pre>
  </div>

  <p>
    This tries to cast a password string as an integer. The database throws a type conversion
    error — and the error message contains the actual password value. The attacker reads
    the password right out of the error text.
  </p>

  <h4>Blind Boolean-Based Injection</h4>

  <p>
    When there are no error messages and no visible data, the attacker can still ask the
    database yes/no questions and observe the application's behavior:
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Blind boolean payloads</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><span class="cmt">-- If the app behaves normally, the condition is TRUE</span>
<span class="str">' AND 1=1 --</span>

<span class="cmt">-- If the app behaves differently, the condition is FALSE</span>
<span class="str">' AND 1=2 --</span>

<span class="cmt">-- Extract first character of the admin password:</span>
<span class="str">' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin') = 'a' --</span>
<span class="str">' AND (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin') = 'b' --</span>
<span class="cmt">-- ...repeat through the alphabet for each character position</span></code></pre>
  </div>

  <p>
    The attacker checks each character of the password one position at a time.
    The page responds differently for true vs false conditions — maybe a redirect vs
    an error page, or a 200 vs a 500 status code. It is slow, but it works.
  </p>

  <h4>Time-Based Blind Injection</h4>

  <p>
    When the application gives absolutely identical responses for true and false conditions,
    the attacker still has one channel left: time.
  </p>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">Time-based payload concept</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><span class="cmt">-- If condition is true, the DB sleeps 5 seconds</span>
<span class="cmt">-- If false, it responds immediately</span>
<span class="str">' AND (SELECT CASE
  WHEN SUBSTR(password,1,1)='a'
  THEN RANDOMBLOB(500000000)
  ELSE 1 END FROM users WHERE username='admin') --</span></code></pre>
  </div>

  <p>
    The attacker measures response time. If the page takes 5 extra seconds to respond,
    the condition was true. This is excruciatingly slow — extracting a single password
    might take hundreds of requests — but it works against any injectable query.
  </p>

  <div class="callout info">
    <div class="callout-title">Automation: sqlmap</div>
    <div class="callout-text">
      This is exactly what tools like <code>sqlmap</code> automate. You point it at a URL,
      it figures out the injection point, detects the database type, determines whether
      it can use error-based, boolean-blind, or time-blind techniques, and then dumps
      your entire database. Automated. That is what you are up against.
    </div>
  </div>
</div>

<hr>

<!-- ════════════════════════════════════════════ -->
<!-- STEP 5: The Fix — Parameterized Queries     -->
<!-- ════════════════════════════════════════════ -->
<div class="step">
  <div class="step-label">Step 5</div>
  <h3>The Fix — Parameterized Queries</h3>

  <p>
    The fix is simple, it is well-known, and it has been available in every major database
    driver for decades. Parameterized queries. Prepared statements. Whatever your stack
    calls them, the principle is identical.
  </p>

  <div class="fix-box">
    <div class="fix-box-title">Secure Implementation</div>

    <div class="code-block">
      <div class="code-header">
        <span class="code-file">routes/login.js (fixed)</span>
        <button class="code-copy">copy</button>
      </div>
      <pre><code>router.<span class="fn">post</span><span class="op">(</span><span class="str">'/login'</span><span class="op">,</span> <span class="op">(</span>req<span class="op">,</span> res<span class="op">)</span> <span class="kw">=&gt;</span> <span class="op">{</span>
  <span class="kw">const</span> <span class="op">{</span> username<span class="op">,</span> password <span class="op">}</span> <span class="op">=</span> req<span class="op">.</span>body<span class="op">;</span>

  <span class="cmt">// SAFE: ? placeholders — data is sent SEPARATELY from query</span>
  <span class="kw">const</span> query <span class="op">=</span> <span class="str">'SELECT * FROM users WHERE username = ? AND password = ?'</span><span class="op">;</span>
  <span class="kw">const</span> user <span class="op">=</span> db.<span class="fn">prepare</span><span class="op">(</span>query<span class="op">).</span><span class="fn">get</span><span class="op">(</span>username<span class="op">,</span> password<span class="op">);</span>

  <span class="kw">if</span> <span class="op">(</span>user<span class="op">)</span> <span class="op">{</span>
    req<span class="op">.</span>session<span class="op">.</span>user <span class="op">=</span> user<span class="op">;</span>
    res.<span class="fn">redirect</span><span class="op">(</span><span class="str">'/dashboard'</span><span class="op">);</span>
  <span class="op">}</span> <span class="kw">else</span> <span class="op">{</span>
    res.<span class="fn">render</span><span class="op">(</span><span class="str">'login'</span><span class="op">,</span> <span class="op">{</span> error<span class="op">:</span> <span class="str">'Invalid credentials'</span> <span class="op">});</span>
  <span class="op">}</span>
<span class="op">});</span></code></pre>
    </div>
  </div>

  <p>
    Now let me explain <em>why</em> this works, because understanding the mechanism matters
    more than memorizing the syntax.
  </p>

  <p>
    When you use parameterized queries, the database driver does not just shove your values into
    the string. Instead, two separate things happen:
  </p>

  <ol>
    <li>
      <strong>The query structure is sent to the database first.</strong> The database parses
      <code>SELECT * FROM users WHERE username = ? AND password = ?</code> and compiles an
      execution plan. At this point, the database knows exactly what the query does — it is a
      SELECT from the users table with two equality conditions. The structure is locked in.
    </li>
    <li>
      <strong>The parameter values are sent separately.</strong> The database plugs them into
      the pre-compiled plan as data. No matter what the values contain — single quotes, SQL
      keywords, semicolons, UNION statements — they are treated as literal string values.
      They cannot modify the query structure because the structure was already compiled.
    </li>
  </ol>

  <p>
    This is not escaping. This is not filtering. This is a fundamentally different mechanism.
    The query logic and the user data travel through separate channels. They never mix.
    That is why parameterized queries are the definitive fix for SQL injection.
  </p>

  <h4>The Diff</h4>

  <div class="code-block">
    <div class="code-header">
      <span class="code-file">routes/login.js</span>
      <button class="code-copy">copy</button>
    </div>
    <pre><code><div class="diff"><span class="diff-ctx">router.post('/login', (req, res) =&gt; {</span>
<span class="diff-ctx">  const { username, password } = req.body;</span>
<span class="diff-rem">  const query = \\\`SELECT * FROM users</span>
<span class="diff-rem">    WHERE username = '\${username}'</span>
<span class="diff-rem">    AND password = '\${password}'\\\`;</span>
<span class="diff-rem">  const user = db.prepare(query).get();</span>
<span class="diff-add">  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';</span>
<span class="diff-add">  const user = db.prepare(query).get(username, password);</span></div></code></pre>
  </div>

  <p>
    Two lines changed. That is it. The fix is trivial. The hard part is making sure you apply
    it everywhere.
  </p>

  <div class="callout info">
    <div class="callout-title">What about ORMs?</div>
    <div class="callout-text">
      ORMs like Sequelize, Prisma, and TypeORM use parameterized queries under the hood, so
      they protect you by default. But every ORM also provides a way to execute raw SQL queries
      for "advanced" use cases. If you use that raw query escape hatch with string concatenation,
      you are right back to being vulnerable. The ORM cannot save you from yourself.
    </div>
  </div>
</div>

<hr>

<!-- ════════════════════════════════════════════ -->
<!-- DEEPER: Real-World Context                  -->
<!-- ════════════════════════════════════════════ -->
<h2>Deeper: Real-World Context</h2>

<p>
  SQL injection was first publicly documented in the late 1990s. It has been in every security
  training course, every OWASP Top 10 list, and every "beginner's guide to hacking" for over
  twenty-five years. And it still shows up. Companies with massive security budgets, dedicated
  AppSec teams, and automated scanning pipelines still get hit by SQL injection. Why?
</p>

<p>
  Because codebases are large. Because developers copy-paste from Stack Overflow. Because
  someone writes a quick admin script that "nobody will ever see" and then it gets promoted
  to production. Because a junior developer does not know what parameterized queries are and
  their pull request gets approved on a Friday afternoon. The vulnerability is simple to
  prevent. The organizational problem of making sure it is prevented everywhere, always,
  in every query, across every team — that is the real challenge.
</p>

<h3>Second-Order SQL Injection</h3>

<p>
  Here is one that catches people off guard. Imagine your application properly parameterizes
  every query when writing data to the database. A user registers with the username
  <code>admin'--</code> and it is safely stored in the users table. No injection happens
  at registration time.
</p>

<p>
  But later, a different part of the application reads that username from the database and
  uses it in a new query <em>with string concatenation</em>. The developer thought: "This
  value came from our own database, so it must be safe." Wrong. The malicious payload was
  sitting in the database, waiting to be used in an unsafe context. This is second-order
  injection, and it is a reminder that the rule is simple and absolute: use parameterized
  queries for every query, regardless of where the data comes from.
</p>

<h3>The Rule</h3>

<div class="callout warn">
  <div class="callout-title">The absolute rule</div>
  <div class="callout-text">
    Use parameterized queries for every SQL query. Not just login forms. Not just
    user-facing endpoints. Every query. Every time. Every table. No exceptions.
    If you are building a SQL string with concatenation or template literals anywhere
    in your codebase, you have a potential SQL injection vulnerability.
  </div>
</div>

<hr>

<!-- ════════════════════════════════════════════ -->
<!-- TASK CHECKLIST                              -->
<!-- ════════════════════════════════════════════ -->
<h2>Lab Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Built the vulnerable login route with string interpolation in SQL</li>
  <li><span class="task-check"></span> Tested authentication bypass with <code>' OR '1'='1' --</code></li>
  <li><span class="task-check"></span> Extracted data with UNION SELECT payload</li>
  <li><span class="task-check"></span> Understood blind injection concepts (boolean-based and time-based)</li>
  <li><span class="task-check"></span> Fixed the route with parameterized queries using ? placeholders</li>
  <li><span class="task-check"></span> Verified the fix blocks all injection attempts</li>
  <li><span class="task-check"></span> Bonus: Run <code>sqlmap</code> against your vulnerable endpoint before and after the fix</li>
</ul>

<!-- ════════════════════════════════════════════ -->
<!-- NAV                                         -->
<!-- ════════════════════════════════════════════ -->
<div class="section-nav">
  <button class="nav-btn" data-prev="setup">Previous: Environment Setup</button>
  <button class="nav-btn" data-next="xss">Next: Cross-Site Scripting</button>
</div>

`;
