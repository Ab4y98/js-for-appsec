window.LESSONS = window.LESSONS || {};
window.LESSONS.nosql = `

<h1 class="lesson-title">Lab 05: NoSQL Injection</h1>

<p class="lesson-subtitle">
  You have already seen how SQL injection works. Now you are going to learn that "schemaless" databases
  have their own injection surface -- and in some ways it is worse, because the attack payloads are
  valid JSON that passes right through most input validation. You will break a MongoDB login, extract
  passwords character by character, and run arbitrary JavaScript inside the database engine.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> MongoDB Setup</h2>

<p>
  Before we start breaking things, let us get MongoDB wired up. If you have been following along from the
  earlier labs, you already have SQLite handling some of your data. We are adding MongoDB alongside it
  because real applications almost never use a single database. You will find SQL databases handling
  transactional data and NoSQL databases handling sessions, user profiles, logs, or document-oriented
  content. Both systems have injection vulnerabilities, and both require different defensive strategies.
  That is why this course covers both -- you need to recognize both attack surfaces in the codebases
  you will work on.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">models/User.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> mongoose <span class="op">=</span> <span class="fn">require</span>(<span class="str">'mongoose'</span>);

<span class="cmt">// Connect to MongoDB</span>
mongoose.<span class="fn">connect</span>(<span class="str">'mongodb://localhost:27017/appsec-course'</span>, {
  useNewUrlParser: <span class="kw">true</span>,
  useUnifiedTopology: <span class="kw">true</span>,
});

<span class="cmt">// Simple user schema</span>
<span class="kw">const</span> userSchema <span class="op">=</span> <span class="kw">new</span> mongoose.<span class="fn">Schema</span>({
  username: { type: String, required: <span class="kw">true</span>, unique: <span class="kw">true</span> },
  password: { type: String, required: <span class="kw">true</span> },
  role:     { type: String, <span class="kw">default</span>: <span class="str">'user'</span> },
  email:    { type: String },
});

module.exports <span class="op">=</span> mongoose.<span class="fn">model</span>(<span class="str">'User'</span>, userSchema);
  </pre>
</div>

<p>
  Nothing unusual here. A straightforward Mongoose schema with username, password, role, and email fields.
  The vulnerability is not in the schema definition -- it is in how we query against it. Seed the database
  with a few users so you have something to attack:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">seed.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> User <span class="op">=</span> <span class="fn">require</span>(<span class="str">'./models/User'</span>);

<span class="kw">async function</span> <span class="fn">seed</span>() {
  <span class="kw">await</span> User.<span class="fn">deleteMany</span>({});
  <span class="kw">await</span> User.<span class="fn">create</span>([
    { username: <span class="str">'admin'</span>,  password: <span class="str">'SuperSecret123'</span>, role: <span class="str">'admin'</span> },
    { username: <span class="str">'alice'</span>,  password: <span class="str">'alice2024'</span>,     role: <span class="str">'user'</span> },
    { username: <span class="str">'bob'</span>,    password: <span class="str">'bobpass!'</span>,      role: <span class="str">'user'</span> },
  ]);
  console.<span class="fn">log</span>(<span class="str">'Seeded users.'</span>);
  process.<span class="fn">exit</span>(<span class="num">0</span>);
}

<span class="fn">seed</span>();
  </pre>
</div>

<div class="callout info">
  <div class="callout-title">Why Both SQL and NoSQL?</div>
  <div class="callout-text">
    I include both in this course because I have seen a dangerous misconception in the industry: "We use
    MongoDB so we are not vulnerable to injection." This is wrong. The injection mechanics are different --
    you are injecting query operators instead of SQL syntax -- but the principle is identical. Untrusted
    input flows into a query, and the database interprets it as instructions instead of data. If you
    only learn SQL injection, you will miss the NoSQL variants when you encounter them in production.
    And you will encounter them.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Build a Vulnerable Login</h2>

<p>
  Here is the login route. Read it carefully, because the vulnerability is subtle if you are not looking
  for it.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/auth.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> User <span class="op">=</span> <span class="fn">require</span>(<span class="str">'../models/User'</span>);
<span class="kw">const</span> router <span class="op">=</span> express.<span class="fn">Router</span>();

<span class="cmt">// VULNERABLE: request body fields are passed directly to the query</span>
router.<span class="fn">post</span>(<span class="str">'/login'</span>, <span class="kw">async</span> (req, res) <span class="op">=></span> {
  <span class="kw">const</span> { username, password } <span class="op">=</span> req.body;

  <span class="kw">const</span> user <span class="op">=</span> <span class="kw">await</span> User.<span class="fn">findOne</span>({ username, password });

  <span class="kw">if</span> (!user) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid credentials'</span> });
  }

  req.session.userId <span class="op">=</span> user._id;
  req.session.role <span class="op">=</span> user.role;
  res.<span class="fn">json</span>({ message: <span class="str">'Login successful'</span>, user: { username: user.username, role: user.role } });
});
  </pre>
</div>

<p>
  At first glance, this looks fine. You take username and password from the request body and query the
  database. If a matching user is found, you log them in. No string concatenation, no template literals,
  no SQL. What could go wrong?
</p>

<p>
  Here is what goes wrong: Express's <code>express.json()</code> middleware parses the request body as JSON.
  JSON can represent objects, not just strings. If the attacker sends a JSON object where <code>password</code>
  is not a string but a MongoDB query operator, Mongoose passes that operator directly into the query. The
  database treats it as an instruction, not as a value to match.
</p>

<p>
  The fundamental issue is that <code>req.body.password</code> is not guaranteed to be a string. It can be
  any valid JSON type: string, number, boolean, null, array, or object. When it is an object containing a
  MongoDB query operator, the database evaluates that operator as part of the query logic. You are no longer
  asking "does this password match?" You are asking the database to evaluate an expression.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> Operator Injection</h2>

<p>
  Let us exploit it. These payloads are simple, effective, and work on every MongoDB-backed login that
  passes request body fields directly into queries.
</p>

<h3>\$ne -- Not Equal</h3>

<div class="attack-box">
  <div class="attack-box-title">Payload: \$ne Operator Injection</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">curl request</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
curl -X POST http://localhost:3000/auth/login \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -d <span class="str">'{"username":"admin","password":{"\$ne":"anything"}}'</span>
    </pre>
  </div>
</div>

<p>
  The query that hits MongoDB becomes:
  <code>User.findOne({ username: "admin", password: { \$ne: "anything" } })</code>. In English: "Find a user
  named admin whose password is NOT EQUAL to 'anything'." Since the admin's actual password is
  <code>SuperSecret123</code>, which is indeed not equal to "anything", the query matches. You are logged in
  as admin without knowing the password.
</p>

<p>
  Think about that for a moment. The attacker does not need to guess the password. They do not need to brute
  force it. They just need to supply a condition that is true. And <code>\$ne</code> plus any wrong value is
  almost always true.
</p>

<h3>\$gt -- Greater Than</h3>

<div class="attack-box">
  <div class="attack-box-title">Payload: \$gt Operator Injection</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">curl request</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
curl -X POST http://localhost:3000/auth/login \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -d <span class="str">'{"username":{"\$gt":""},"password":{"\$gt":""}}'</span>
    </pre>
  </div>
</div>

<p>
  This is even worse. Both fields use <code>\$gt: ""</code>, which means "greater than empty string."
  Every non-empty string is greater than an empty string, so this matches the first user in the collection.
  Depending on your MongoDB's internal ordering, that is often the admin user. The attacker does not even
  need to know a valid username.
</p>

<div class="callout warn">
  <div class="callout-title">The Full Operator Arsenal</div>
  <div class="callout-text">
    MongoDB's query language includes dozens of operators, and many of them are useful to an attacker.
    <code>\$ne</code> (not equal) and <code>\$gt</code> (greater than) are the most common, but
    <code>\$lt</code> (less than), <code>\$regex</code> (regular expression matching),
    <code>\$exists</code> (field exists), <code>\$in</code> (value in array), and <code>\$nin</code>
    (value not in array) all work as injection operators. The more powerful MongoDB's query language
    is, the larger the attack surface becomes when you pass untrusted input directly into queries.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> Advanced -- \$regex and \$where</h2>

<p>
  The basic operator injections get you in. But what if you want to actually extract data? What if you
  want to figure out what the admin's password is, not just bypass it?
</p>

<h3>\$regex for Character-by-Character Extraction</h3>

<div class="attack-box">
  <div class="attack-box-title">Payload: \$regex Data Exfiltration</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">curl requests -- sequential probing</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="cmt"># Does the admin password start with 'S'?</span>
curl -X POST http://localhost:3000/auth/login \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -d <span class="str">'{"username":"admin","password":{"\$regex":"^S"}}'</span>
<span class="cmt"># 200 OK -- yes, it starts with 'S'</span>

<span class="cmt"># Does it start with 'Su'?</span>
curl -X POST http://localhost:3000/auth/login \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -d <span class="str">'{"username":"admin","password":{"\$regex":"^Su"}}'</span>
<span class="cmt"># 200 OK -- yes</span>

<span class="cmt"># Does it start with 'Sup'?</span>
curl -X POST http://localhost:3000/auth/login \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -d <span class="str">'{"username":"admin","password":{"\$regex":"^Sup"}}'</span>
<span class="cmt"># 200 OK -- keep going...</span>

<span class="cmt"># An attacker scripts this to try every character at every position.</span>
<span class="cmt"># Eventually: ^SuperSecret123 -- full password extracted.</span>
    </pre>
  </div>
</div>

<p>
  The <code>\$regex</code> operator lets the attacker probe the password one character at a time. They send
  <code>{"password":{"$regex":"^a"}}</code>, <code>{"password":{"$regex":"^b"}}</code>, and so on until they
  get a successful login response. Then they move to the second character:
  <code>{"password":{"$regex":"^Sa"}}</code>, <code>{"password":{"$regex":"^Sb"}}</code>, etc. An automated
  script can extract an entire password in seconds. This is essentially a blind injection technique --
  the same concept as blind SQL injection, adapted for MongoDB's query language.
</p>

<p>
  This is particularly dangerous because even if your application does not return the password in the
  response body, the attacker uses the login success or failure as a boolean oracle. "Did the query match?
  Yes or no?" That single bit of information, repeated many times, leaks the entire field value.
</p>

<h3>\$where -- JavaScript Execution Inside MongoDB</h3>

<div class="attack-box">
  <div class="attack-box-title">Payload: \$where JavaScript Injection</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">curl request</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
curl -X POST http://localhost:3000/auth/login \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -d <span class="str">'{"username":"admin","\$where":"this.password.length > 5"}'</span>
    </pre>
  </div>
</div>

<p>
  This one should make you uncomfortable. The <code>\$where</code> operator tells MongoDB to evaluate a
  JavaScript expression for each document in the collection. <code>this</code> refers to the current
  document being evaluated. So <code>this.password.length > 5</code> checks whether the document's password
  field has more than five characters. If it does, the document matches the query.
</p>

<p>
  Think about what <code>\$where</code> really is: it is <code>eval()</code> inside your database. The
  attacker is sending arbitrary JavaScript that runs in the context of your MongoDB server. In older
  versions of MongoDB (before 4.4), <code>\$where</code> could even access certain server-side functions.
  Modern MongoDB restricts what <code>\$where</code> can do, and most production deployments disable it
  entirely. But legacy applications are everywhere, and many of them still allow it.
</p>

<p>
  Even with modern restrictions, <code>\$where</code> is expensive. An attacker can use it for denial of
  service by sending expressions that force MongoDB to evaluate JavaScript on every document in a large
  collection. A query like <code>{"\$where":"sleep(5000)"}</code> can tie up database resources and
  degrade performance for all users.
</p>

<div class="callout info">
  <div class="callout-title">The \$where Timeline</div>
  <div class="callout-text">
    MongoDB has been progressively restricting <code>\$where</code> over the years. In MongoDB 3.x,
    <code>\$where</code> could do quite a lot. MongoDB 4.2 deprecated many server-side JavaScript
    features. MongoDB 5.0 removed the internal JavaScript engine for map-reduce operations entirely.
    But <code>\$where</code> still works in query filters even in modern versions -- it is just more
    sandboxed. The lesson is not "this is old and irrelevant." The lesson is that your application
    probably talks to databases of many different versions, and you cannot assume the database will
    protect you.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> The Fix -- Type Checking and Sanitization</h2>

<p>
  The root cause is clear: we trusted that <code>req.body.password</code> would be a string, but JSON
  parsing turns objects into... objects. The fix has multiple layers, and you should implement all of them.
</p>

<div class="fix-box">
  <div class="fix-box-title">Fixed: Type Checking Before Query</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">routes/auth.js</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> User <span class="op">=</span> <span class="fn">require</span>(<span class="str">'../models/User'</span>);
<span class="kw">const</span> router <span class="op">=</span> express.<span class="fn">Router</span>();

router.<span class="fn">post</span>(<span class="str">'/login'</span>, <span class="kw">async</span> (req, res) <span class="op">=></span> {
  <span class="kw">const</span> { username, password } <span class="op">=</span> req.body;

  <span class="cmt">// Type check: reject anything that is not a string</span>
  <span class="kw">if</span> (<span class="kw">typeof</span> username <span class="op">!==</span> <span class="str">'string'</span> || <span class="kw">typeof</span> password <span class="op">!==</span> <span class="str">'string'</span>) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">400</span>).<span class="fn">json</span>({ error: <span class="str">'Username and password must be strings.'</span> });
  }

  <span class="cmt">// Explicit coercion as defense in depth</span>
  <span class="kw">const</span> user <span class="op">=</span> <span class="kw">await</span> User.<span class="fn">findOne</span>({
    username: <span class="fn">String</span>(username),
    password: <span class="fn">String</span>(password),
  });

  <span class="kw">if</span> (!user) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">401</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid credentials'</span> });
  }

  req.session.userId <span class="op">=</span> user._id;
  req.session.role <span class="op">=</span> user.role;
  res.<span class="fn">json</span>({ message: <span class="str">'Login successful'</span>, user: { username: user.username, role: user.role } });
});
    </pre>
  </div>
</div>

<p>
  The <code>typeof</code> check is the primary defense. If <code>password</code> is an object like
  <code>{"\$ne":"anything"}</code>, then <code>typeof password</code> returns <code>"object"</code>, not
  <code>"string"</code>, and the request is rejected before it ever touches the database. The
  <code>String()</code> coercion is a second layer of defense -- if an object somehow gets past the type
  check, <code>String({"\$ne":"anything"})</code> returns <code>"[object Object]"</code>, which will not
  match any password in the database.
</p>

<h3>express-mongo-sanitize Middleware</h3>

<div class="fix-box">
  <div class="fix-box-title">Fixed: Global Sanitization Middleware</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">app.js</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> mongoSanitize <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express-mongo-sanitize'</span>);

<span class="kw">const</span> app <span class="op">=</span> <span class="fn">express</span>();

app.<span class="fn">use</span>(express.<span class="fn">json</span>());

<span class="cmt">// Strips any keys that start with '$' from req.body, req.query, and req.params</span>
app.<span class="fn">use</span>(<span class="fn">mongoSanitize</span>());

<span class="cmt">// Now every route is protected from basic operator injection.</span>
<span class="cmt">// But do not rely on this alone -- type checking is still essential.</span>
    </pre>
  </div>
</div>

<p>
  The <code>express-mongo-sanitize</code> middleware walks through <code>req.body</code>,
  <code>req.query</code>, and <code>req.params</code> and strips out any keys that start with
  <code>\$</code>. So <code>{"\$ne":"anything"}</code> becomes <code>{}</code> before your route handler
  ever sees it. This is a good global safety net, but it is not sufficient on its own. I will explain why
  in the next section.
</p>

<h3>Mongoose Strict Mode</h3>

<p>
  Mongoose schemas have a <code>strict</code> option that is enabled by default. When strict mode is on,
  any fields in a document that are not defined in the schema are silently stripped before the document
  is saved. This does not directly prevent query injection, but it is part of a defense-in-depth strategy.
  Make sure you are not disabling it:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Schema with explicit strict mode</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> userSchema <span class="op">=</span> <span class="kw">new</span> mongoose.<span class="fn">Schema</span>({
  username: { type: String, required: <span class="kw">true</span> },
  password: { type: String, required: <span class="kw">true</span> },
  role:     { type: String, <span class="kw">default</span>: <span class="str">'user'</span>, <span class="kw">enum</span>: [<span class="str">'user'</span>, <span class="str">'admin'</span>] },
}, { strict: <span class="kw">true</span> }); <span class="cmt">// default, but be explicit</span>
  </pre>
</div>

<p>
  Also note the <code>enum</code> validator on the <code>role</code> field. Schema-level validation is
  another layer of defense. Even if an attacker manages to inject data past your route-level checks,
  Mongoose will reject documents that do not conform to the schema.
</p>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> What Sanitize Misses</h2>

<h3>Nested Objects</h3>

<p>
  The <code>express-mongo-sanitize</code> middleware strips top-level keys starting with <code>\$</code>.
  But what about nested structures? Consider a query against a document with embedded sub-documents. If
  your application constructs queries that reach into nested fields, an attacker might be able to inject
  operators at a nesting level that the sanitizer does not reach. Most modern versions of the middleware
  handle recursive stripping, but older versions did not. Always verify the behavior of your specific
  version, and never assume the middleware catches everything.
</p>

<h3>Schema Validation at Every Layer</h3>

<p>
  I have reviewed applications where the API gateway validated input, but an internal microservice that
  also accepted queries from a message queue did not. The attacker exploited the message queue path, which
  bypassed the API gateway's sanitization entirely. The lesson: validate at every layer that accepts input.
  Your Express middleware is one layer. Your Mongoose schema is another. Your database-level validation
  rules are a third. Each one catches attacks that the others might miss.
</p>

<h3>"Schemaless" Does Not Mean "Validation-Free"</h3>

<p>
  One of MongoDB's selling points is flexibility -- you can store documents without a rigid schema. Some
  teams interpret this as "we do not need to validate our data." This is a catastrophic misunderstanding.
  The absence of a database-enforced schema means your application code is the only thing standing between
  user input and the database. If your application code does not validate types, lengths, formats, and
  allowed values, then there is no validation at all. I have seen MongoDB collections in production where
  the same field contains strings in some documents, numbers in others, and nested objects in others. That
  kind of inconsistency is not just a data quality problem -- it is a security problem, because it means
  the application is not enforcing any expectations about what data looks like, which means an attacker
  can send whatever they want.
</p>

<p>
  The fix is to treat "schemaless" as "schema-enforced-in-code." Use Mongoose schemas with strict mode.
  Add validators for every field. Use <code>enum</code> constraints for fields with known valid values.
  Add <code>minlength</code> and <code>maxlength</code> for strings. The database may not enforce these
  constraints, but your ORM layer can and should.
</p>

<div class="callout warn">
  <div class="callout-title">Defense in Depth Summary</div>
  <div class="callout-text">
    No single defense is sufficient. Combine all of these: type checking with <code>typeof</code> before
    every query, explicit type coercion with <code>String()</code> as a fallback, global sanitization
    with <code>express-mongo-sanitize</code>, Mongoose strict mode and schema validators, and
    application-level input validation for format and length. An attacker has to get through every
    layer. Make sure each layer is actually doing its job.
  </div>
</div>

<hr>

<h2>Lab 05 Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Set up MongoDB with Mongoose and create a User schema with seed data</li>
  <li><span class="task-check"></span> Build the vulnerable login route that passes req.body fields directly to findOne()</li>
  <li><span class="task-check"></span> Exploit it with \$ne and \$gt operator injection to bypass authentication</li>
  <li><span class="task-check"></span> Use \$regex injection to extract the admin password character by character</li>
  <li><span class="task-check"></span> Add typeof checks and String() coercion to the login route</li>
  <li><span class="task-check"></span> Install and configure express-mongo-sanitize as global middleware</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="cmdi">Previous: Command Injection</button>
  <button class="nav-btn" data-next="csrf">Next: CSRF</button>
</div>

`;
