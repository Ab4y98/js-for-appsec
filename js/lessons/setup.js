window.LESSONS = window.LESSONS || {};
window.LESSONS.setup = `

<h1 class="lesson-title">Lab 01: Environment Setup</h1>

<p class="lesson-subtitle">
  Lab 01: Scaffold the project, install every dependency, initialize the databases, and get our deliberately
  vulnerable Express application running. Every decision here is intentional -- even the bad ones.
</p>

<hr>

<h2>Prerequisites</h2>

<p>
  Before we write a single line of code, let me walk you through what you need installed and why each piece matters.
  I am not going to just hand you a list -- I want you to understand the role every tool plays so that nothing
  feels like magic.
</p>

<div class="step">
  <div class="step-label">1</div>
  <div>
    <strong>Node.js 18+ and npm</strong>
    <p>
      We need Node.js 18 or later. Not because the code strictly requires it, but because 18 is the oldest
      LTS release that still receives security patches. Running vulnerable-by-design code on an <em>also</em>
      vulnerable runtime would just be confusing when things break. npm ships with Node.js and handles our
      dependency management. You can verify your versions in the terminal:
    </p>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">Terminal</span>
        <button class="code-copy">Copy</button>
      </div>
      <pre>node --version    <span class="cmt"># Should be v18.x.x or higher</span>
npm --version     <span class="cmt"># Should be 9.x.x or higher</span></pre>
    </div>
    <p>
      If you are behind, grab the latest LTS from <strong>nodejs.org</strong>. I recommend using nvm (Node Version
      Manager) if you juggle multiple projects, but a direct install works fine for this course.
    </p>
  </div>
</div>

<div class="step">
  <div class="step-label">2</div>
  <div>
    <strong>A Terminal</strong>
    <p>
      You will spend most of this course in a terminal. On macOS, Terminal.app or iTerm2. On Windows, PowerShell
      or Windows Terminal. On Linux, whatever you already use. The specific terminal does not matter as long as
      you can run Node.js and npm commands. If you have never used a terminal before, this course assumes you are
      at least comfortable with <code>cd</code>, <code>ls</code>, and running commands.
    </p>
  </div>
</div>

<div class="step">
  <div class="step-label">3</div>
  <div>
    <strong>A Text Editor or IDE</strong>
    <p>
      VS Code is the obvious recommendation -- its JavaScript support is excellent and you will appreciate the
      integrated terminal. But Vim, Sublime Text, WebStorm, or literally anything that edits text files will work.
      You do not need any special extensions for this course, though a good syntax highlighter makes reading
      exploit payloads much more pleasant.
    </p>
  </div>
</div>

<div class="step">
  <div class="step-label">4</div>
  <div>
    <strong>SQLite3</strong>
    <p>
      We use SQLite for the SQL injection labs. Why SQLite and not PostgreSQL or MySQL? Two reasons.
      First, SQLite is serverless -- it stores the entire database in a single file, which means zero configuration.
      You will not waste twenty minutes debugging a Postgres connection string when you should be learning about
      injection attacks. Second, the SQL injection techniques you learn on SQLite transfer directly to every other
      relational database. An injection is an injection regardless of dialect.
    </p>
    <p>
      You do not need to install SQLite separately. The <code>better-sqlite3</code> npm package bundles its
      own native SQLite binary. It compiles during <code>npm install</code>, which means you need a C++ build
      toolchain (Xcode Command Line Tools on macOS, <code>build-essential</code> on Ubuntu, or the Visual Studio
      C++ build tools on Windows). If you have ever installed a native npm module before, you are probably fine.
    </p>
  </div>
</div>

<div class="step">
  <div class="step-label">5</div>
  <div>
    <strong>MongoDB</strong>
    <p>
      The NoSQL injection lab requires MongoDB. We need a second database engine specifically because NoSQL
      injection looks and feels completely different from SQL injection, and understanding both is critical for
      any developer working with modern stacks. Many real-world applications use both SQL and NoSQL databases
      side by side, so you need to know how to defend both.
    </p>
    <p>
      The easiest option is MongoDB Community Edition installed locally. Alternatively, you can use a free-tier
      MongoDB Atlas cluster if you prefer not to install it on your machine. Either way, make sure you can
      connect to it with <code>mongosh</code> before moving on.
    </p>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">Terminal</span>
        <button class="code-copy">Copy</button>
      </div>
      <pre>mongosh --eval "db.runCommand({ ping: 1 })"   <span class="cmt"># Should return { ok: 1 }</span></pre>
    </div>
    <p>
      <a href="https://www.mongodb.com/try/download/community" target="_blank">Download MongoDB Community Edition</a>
      <br>
      <a href="https://www.mongodb.com/try/download/shell" target="_blank">Download MongoDB Shell</a>
    </p>
  </div>
</div>

<hr>

<h2>Project Scaffolding</h2>

<p>
  Let us build the project from nothing. Open your terminal, navigate to wherever you keep projects, and follow
  along. I will explain every step.
</p>

<div class="step">
  <div class="step-label">1</div>
  <div>
    <strong>Create the project directory and initialize npm</strong>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">Terminal</span>
        <button class="code-copy">Copy</button>
      </div>
      <pre>mkdir vuln-app
<span class="kw">cd</span> vuln-app
npm init -y</pre>
    </div>
    <p>
      The <code>-y</code> flag accepts all defaults. We are not publishing this to npm, so the metadata does not
      matter. What matters is that we have a <code>package.json</code> to track our dependencies.
    </p>
  </div>
</div>

<div class="step">
  <div class="step-label">2</div>
  <div>
    <strong>Install dependencies</strong>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">Terminal</span>
        <button class="code-copy">Copy</button>
      </div>
      <pre>npm install express better-sqlite3 mongoose jsonwebtoken bcrypt express-session node-serialize csurf helmet ejs</pre>
    </div>
    <p>
      That is a lot of packages. Let me explain every single one, because nothing in this project is arbitrary.
    </p>
  </div>
</div>

<hr>

<h2>Dependency Breakdown</h2>

<p>
  Understanding your dependencies is itself a security skill. In Lab 10, you will audit these very packages
  for known vulnerabilities. For now, here is what each one does and why it is in our project.
</p>

<h3>express</h3>
<p>
  The web framework that handles routing, middleware, and HTTP request/response management. Express is the most
  widely used Node.js web framework, which makes it the most relevant target for learning web security. The
  vulnerabilities you find here will look almost identical to what you encounter in real-world Express apps.
  We are intentionally using Express with minimal configuration at first -- no security hardening, no input
  sanitization middleware, nothing. That comes later, when you understand <em>why</em> each safeguard matters.
</p>

<h3>better-sqlite3</h3>
<p>
  A synchronous SQLite driver for Node.js. I chose this over the more common <code>sqlite3</code> package for
  one simple reason: it is synchronous. When you are learning SQL injection, you want to see the query go in and
  the result come out without juggling callbacks or promises. The synchronous API makes the injection mechanics
  crystal clear. It also compiles faster and is generally more pleasant to work with. The SQL injection
  techniques are identical regardless of which driver you use.
</p>

<h3>mongoose</h3>
<p>
  The MongoDB ODM (Object Document Mapper) that we use for the NoSQL injection lab. Mongoose provides schema
  validation and query building, but -- and this is the important part -- it does <em>not</em> automatically
  prevent all injection attacks. You will see exactly where its protections fall short and where you need to
  add your own defenses.
</p>

<h3>jsonwebtoken</h3>
<p>
  Handles JSON Web Token creation and verification. We use this in the Broken Authentication lab to demonstrate
  how JWTs can be forged, tampered with, and exploited when implemented carelessly. You will forge tokens, exploit
  the infamous <code>alg: "none"</code> vulnerability, and understand why JWT-based authentication requires
  extremely careful implementation.
</p>

<h3>bcrypt</h3>
<p>
  A password hashing library. This is part of the <em>fix</em> for the Broken Authentication lab, not the
  vulnerability. You will start with plaintext and MD5-hashed passwords (the vulnerable version), then migrate
  to bcrypt with proper salt rounds as the remediation. bcrypt is deliberately slow by design, and you will
  understand exactly why that slowness is a feature, not a bug.
</p>

<h3>express-session</h3>
<p>
  Server-side session management middleware. Sessions are a recurring theme across multiple labs -- CSRF,
  Broken Authentication, and Security Misconfiguration all involve session handling. We start with an intentionally
  weak session configuration (predictable secret, no secure flags, no expiration) and progressively harden it
  as you work through the labs.
</p>

<h3>node-serialize</h3>
<p>
  This package is <strong>deliberately insecure</strong>, and that is exactly why it is here. It provides
  serialization and deserialization of JavaScript objects, including functions. In the Insecure Deserialization
  lab, you will use it to achieve actual remote code execution on your own machine. This is not a theoretical
  attack -- you will pop a reverse shell through a JSON payload. In production, you would never use this package.
  Here, it is the entire point.
</p>

<div class="callout warn">
  <div class="callout-title">About node-serialize</div>
  <div class="callout-text">
    The <code>node-serialize</code> package has a known RCE vulnerability and should <strong>never</strong> be used
    in production code. We include it here purely for educational purposes. This is a training environment running
    on localhost. Do not install this package in any application that faces the internet.
  </div>
</div>

<h3>csurf</h3>
<p>
  CSRF protection middleware for Express. This is another "fix" package -- you will not use it until the CSRF
  lab, where you first exploit Cross-Site Request Forgery without any protection, then add <code>csurf</code>
  to see how anti-CSRF tokens prevent the attack. It integrates with <code>express-session</code> to generate
  and validate tokens automatically.
</p>

<h3>helmet</h3>
<p>
  A collection of middleware that sets security-related HTTP headers. Helmet handles Content-Security-Policy,
  X-Content-Type-Options, Strict-Transport-Security, and a dozen other headers that browsers use to enforce
  security policies. You will start without Helmet (the vulnerable state), see exactly what attacks those missing
  headers enable, and then add Helmet to close those gaps.
</p>

<h3>ejs</h3>
<p>
  Embedded JavaScript templating. We use server-side rendering with EJS because it gives us direct control over
  how user input gets embedded in HTML responses. This is critical for the XSS lab. Modern frontend frameworks
  like React automatically escape output in most cases, which would hide the vulnerability we need to study. EJS
  lets you choose between escaped (<code>&lt;%= %&gt;</code>) and unescaped (<code>&lt;%- %&gt;</code>) output,
  and that choice is exactly where XSS vulnerabilities live.
</p>

<hr>

<h2>The Application Boilerplate</h2>

<p>
  Now let us create the main application file. Read every line carefully -- I am going to explain not just what
  the code does, but what is <em>wrong</em> with it and why we are writing it that way on purpose.
</p>

<div class="step">
  <div class="step-label">3</div>
  <div>
    <strong>Create app.js</strong>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">app.js</span>
        <button class="code-copy">Copy</button>
      </div>
      <pre><span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> session <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express-session'</span>);
<span class="kw">const</span> path <span class="op">=</span> <span class="fn">require</span>(<span class="str">'path'</span>);

<span class="kw">const</span> app <span class="op">=</span> <span class="fn">express</span>();

<span class="cmt">// Parse incoming request bodies</span>
app.<span class="fn">use</span>(express.<span class="fn">json</span>());
app.<span class="fn">use</span>(express.<span class="fn">urlencoded</span>({ extended: <span class="kw">true</span> }));

<span class="cmt">// Serve static files</span>
app.<span class="fn">use</span>(express.<span class="fn">static</span>(path.<span class="fn">join</span>(__dirname, <span class="str">'public'</span>)));

<span class="cmt">// Set up EJS as the view engine</span>
app.<span class="fn">set</span>(<span class="str">'view engine'</span>, <span class="str">'ejs'</span>);
app.<span class="fn">set</span>(<span class="str">'views'</span>, path.<span class="fn">join</span>(__dirname, <span class="str">'views'</span>));

<span class="cmt">// --- INTENTIONALLY INSECURE SESSION CONFIG ---</span>
app.<span class="fn">use</span>(<span class="fn">session</span>({
  secret: <span class="str">'keyboard cat'</span>,           <span class="cmt">// Weak, hard-coded secret</span>
  resave: <span class="kw">false</span>,
  saveUninitialized: <span class="kw">true</span>,          <span class="cmt">// Creates sessions for anonymous users</span>
  cookie: {
    secure: <span class="kw">false</span>,                   <span class="cmt">// Cookies sent over HTTP (not HTTPS)</span>
    httpOnly: <span class="kw">false</span>,                 <span class="cmt">// JavaScript can read cookies (XSS risk)</span>
    maxAge: <span class="kw">null</span>                     <span class="cmt">// Session never expires</span>
  }
}));

<span class="cmt">// No Helmet. No CORS config. No rate limiting.</span>
<span class="cmt">// No CSRF protection. These are all intentional.</span>

<span class="cmt">// --- ROUTES ---</span>
app.<span class="fn">get</span>(<span class="str">'/'</span>, (req, res) <span class="op">=></span> {
  res.<span class="fn">render</span>(<span class="str">'index'</span>, { user: req.session.user <span class="op">||</span> <span class="kw">null</span> });
});

<span class="cmt">// --- ERROR HANDLING (intentionally verbose) ---</span>
app.<span class="fn">use</span>((err, req, res, next) <span class="op">=></span> {
  <span class="cmt">// Leaks stack traces to the client -- Security Misconfiguration</span>
  res.<span class="fn">status</span>(<span class="num">500</span>).<span class="fn">json</span>({
    error: err.message,
    stack: err.stack           <span class="cmt">// Never do this in production</span>
  });
});

<span class="kw">const</span> PORT <span class="op">=</span> process.env.PORT <span class="op">||</span> <span class="num">3000</span>;
app.<span class="fn">listen</span>(PORT, () <span class="op">=></span> {
  console.<span class="fn">log</span>(<span class="str">\`Server running on http://localhost:\${PORT}\`</span>);
});</pre>
    </div>

    <p>
      Let us walk through what is intentionally wrong here, because understanding these decisions is essential:
    </p>

    <ul>
      <li><strong><code>'keyboard cat'</code> as the session secret:</strong> This is a hardcoded, widely-known string. In production, an attacker who knows your session secret can forge session cookies. We use it here because it is the default from the Express docs, and a shocking number of real applications ship with exactly this value.</li>
      <li><strong><code>saveUninitialized: true</code>:</strong> This creates a session for every visitor, even unauthenticated ones. It wastes server resources and can be used for session fixation attacks.</li>
      <li><strong><code>secure: false</code>:</strong> Session cookies will be sent over plain HTTP. An attacker on the same network can intercept them trivially.</li>
      <li><strong><code>httpOnly: false</code>:</strong> This is the big one for the XSS lab. With httpOnly disabled, JavaScript running in the browser can read <code>document.cookie</code>. When you inject a XSS payload in Lab 04, this is how you will steal session tokens.</li>
      <li><strong><code>maxAge: null</code>:</strong> The session never expires. If an attacker steals a session cookie, it works forever.</li>
      <li><strong>No Helmet:</strong> No security headers are set. No Content-Security-Policy, no X-Frame-Options, nothing. The browser is flying blind.</li>
      <li><strong>Verbose error handler:</strong> The error handler sends the full stack trace to the client. This leaks file paths, dependency versions, and internal architecture to anyone who triggers an error.</li>
    </ul>

    <p>
      Every single one of these issues will be exploited and fixed in a later lab. For now, this is our
      intentionally broken baseline.
    </p>
  </div>
</div>

<hr>

<h2>Database Initialization</h2>

<p>
  Our application uses SQLite for relational data (users, posts, notes) and MongoDB for document-based data.
  Let us set up the SQLite database first with a schema and seed data.
</p>

<div class="step">
  <div class="step-label">4</div>
  <div>
    <strong>Create the database initialization script</strong>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">db/init.js</span>
        <button class="code-copy">Copy</button>
      </div>
      <pre><span class="kw">const</span> Database <span class="op">=</span> <span class="fn">require</span>(<span class="str">'better-sqlite3'</span>);
<span class="kw">const</span> path <span class="op">=</span> <span class="fn">require</span>(<span class="str">'path'</span>);

<span class="kw">const</span> db <span class="op">=</span> <span class="kw">new</span> <span class="fn">Database</span>(path.<span class="fn">join</span>(__dirname, <span class="str">'app.db'</span>));

<span class="cmt">// Enable WAL mode for better concurrent read performance</span>
db.<span class="fn">pragma</span>(<span class="str">'journal_mode = WAL'</span>);

<span class="cmt">// --- SCHEMA ---</span>
db.<span class="fn">exec</span>(<span class="str">\`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    email TEXT,
    bio TEXT
  );

  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    private INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
\`</span>);

<span class="cmt">// --- SEED DATA ---</span>
<span class="cmt">// Intentionally using weak, plaintext passwords</span>
<span class="kw">const</span> seedUsers <span class="op">=</span> [
  { username: <span class="str">'admin'</span>,   password: <span class="str">'admin123'</span>,     role: <span class="str">'admin'</span>, email: <span class="str">'admin@vuln-app.local'</span> },
  { username: <span class="str">'alice'</span>,   password: <span class="str">'password'</span>,     role: <span class="str">'user'</span>,  email: <span class="str">'alice@vuln-app.local'</span> },
  { username: <span class="str">'bob'</span>,     password: <span class="str">'letmein'</span>,      role: <span class="str">'user'</span>,  email: <span class="str">'bob@vuln-app.local'</span> },
  { username: <span class="str">'charlie'</span>, password: <span class="str">'qwerty'</span>,       role: <span class="str">'user'</span>,  email: <span class="str">'charlie@vuln-app.local'</span> },
];

<span class="kw">const</span> insertUser <span class="op">=</span> db.<span class="fn">prepare</span>(<span class="str">\`
  INSERT OR IGNORE INTO users (username, password, role, email)
  VALUES (@username, @password, @role, @email)
\`</span>);

<span class="kw">const</span> insertPost <span class="op">=</span> db.<span class="fn">prepare</span>(<span class="str">\`
  INSERT OR IGNORE INTO posts (user_id, title, body)
  VALUES (@user_id, @title, @body)
\`</span>);

<span class="kw">const</span> insertNote <span class="op">=</span> db.<span class="fn">prepare</span>(<span class="str">\`
  INSERT OR IGNORE INTO notes (user_id, content, private)
  VALUES (@user_id, @content, @private)
\`</span>);

<span class="cmt">// Insert seed data inside a transaction for performance</span>
<span class="kw">const</span> seed <span class="op">=</span> db.<span class="fn">transaction</span>(() <span class="op">=></span> {
  <span class="kw">for</span> (<span class="kw">const</span> user <span class="kw">of</span> seedUsers) {
    insertUser.<span class="fn">run</span>(user);
  }

  <span class="cmt">// Sample posts</span>
  insertPost.<span class="fn">run</span>({ user_id: <span class="num">1</span>, title: <span class="str">'Welcome to the Platform'</span>, body: <span class="str">'This is the first post by the admin.'</span> });
  insertPost.<span class="fn">run</span>({ user_id: <span class="num">2</span>, title: <span class="str">'Hello World'</span>, body: <span class="str">'Alice here, just testing things out.'</span> });
  insertPost.<span class="fn">run</span>({ user_id: <span class="num">3</span>, title: <span class="str">'My First Post'</span>, body: <span class="str">'Bob checking in.'</span> });

  <span class="cmt">// Private notes (for IDOR lab)</span>
  insertNote.<span class="fn">run</span>({ user_id: <span class="num">1</span>, content: <span class="str">'Admin secret: the backup key is stored in /etc/backup.key'</span>, private: <span class="num">1</span> });
  insertNote.<span class="fn">run</span>({ user_id: <span class="num">2</span>, content: <span class="str">'Alice personal note: remember to change password'</span>, private: <span class="num">1</span> });
  insertNote.<span class="fn">run</span>({ user_id: <span class="num">3</span>, content: <span class="str">'Bob draft: working on new feature for the API'</span>, private: <span class="num">1</span> });
});

<span class="fn">seed</span>();

console.<span class="fn">log</span>(<span class="str">'Database initialized with seed data.'</span>);

module.exports <span class="op">=</span> db;</pre>
    </div>

    <p>
      There is a lot to unpack here, and all of it matters:
    </p>

    <ul>
      <li><strong>Plaintext passwords:</strong> Yes, the passwords are stored as plaintext strings. Not hashed. Not salted. Just raw strings sitting in the database. This is the vulnerable state for Lab 05 (Broken Authentication). You will see exactly how trivial it is to "crack" these passwords when there is nothing to crack -- they are right there in the clear. The bcrypt fix comes later.</li>
      <li><strong><code>admin/admin123</code>:</strong> This is the most common default credential pair in the world. Automated scanners try it on every login form they find. We use it intentionally because it models what you will actually encounter in the wild.</li>
      <li><strong>Private notes:</strong> The <code>notes</code> table has a <code>private</code> column. In the IDOR lab, you will access other users' private notes by simply changing the note ID in the URL. The database marks them as private, but the application code will fail to check ownership.</li>
      <li><strong>Admin secrets in notes:</strong> The admin's private note contains a fake file path. This models the real-world pattern where sensitive operational data lives in user-accessible database records with insufficient access controls.</li>
    </ul>
  </div>
</div>

<div class="callout info">
  <div class="callout-title">Why plaintext passwords?</div>
  <div class="callout-text">
    You might be asking why we do not start with hashed passwords from the beginning. The answer is pedagogical.
    When you dump the users table and see <code>admin123</code> sitting right there in the password column, it
    hits differently than reading about "insufficient cryptographic protection" in a textbook. That visceral
    reaction -- "oh no, anyone with database access can read every password" -- is exactly the feeling that will
    stay with you every time you design a user table in the future.
  </div>
</div>

<hr>

<h2>Project Structure</h2>

<p>
  After setup, your project directory should look like this:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">Project Structure</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>vuln-app/
  app.js                <span class="cmt"># Main Express application</span>
  package.json          <span class="cmt"># Dependencies and scripts</span>
  db/
    init.js             <span class="cmt"># SQLite schema + seed data</span>
    app.db              <span class="cmt"># SQLite database file (auto-created)</span>
  views/
    index.ejs           <span class="cmt"># Main page template</span>
    login.ejs           <span class="cmt"># Login form (Lab 02)</span>
    search.ejs          <span class="cmt"># Search page (Lab 02)</span>
    profile.ejs         <span class="cmt"># User profile (Lab 04, 06)</span>
  public/
    css/
      style.css         <span class="cmt"># Minimal styling</span>
  routes/
    auth.js             <span class="cmt"># Authentication routes (Lab 02, 05)</span>
    posts.js            <span class="cmt"># Post CRUD routes (Lab 04, 06)</span>
    notes.js            <span class="cmt"># Notes routes (Lab 06)</span>
    admin.js            <span class="cmt"># Admin panel routes (Lab 11)</span></pre>
</div>

<p>
  You do not need to create all of these files right now. Each lab will introduce the files it needs.
  For this lab, you only need <code>app.js</code>, <code>db/init.js</code>, and a basic
  <code>views/index.ejs</code>.
</p>

<hr>

<h2>The Index View</h2>

<p>
  Our app.js renders <code>views/index.ejs</code> on the root route, so we need to create it. This is the
  landing page — it shows the logged-in user's name if a session exists, or a login link if not. Create the
  <code>views</code> directory and add this file:
</p>

<div class="step">
  <div class="step-label">5</div>
  <div>
    <strong>Create views/index.ejs</strong>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">views/index.ejs</span>
        <button class="code-copy">Copy</button>
      </div>
      <pre><span class="op">&lt;!</span><span class="kw">DOCTYPE</span> html<span class="op">&gt;</span>
<span class="op">&lt;</span><span class="kw">html</span> lang<span class="op">=</span><span class="str">"en"</span><span class="op">&gt;</span>
<span class="op">&lt;</span><span class="kw">head</span><span class="op">&gt;</span>
  <span class="op">&lt;</span><span class="kw">meta</span> charset<span class="op">=</span><span class="str">"UTF-8"</span><span class="op">&gt;</span>
  <span class="op">&lt;</span><span class="kw">meta</span> name<span class="op">=</span><span class="str">"viewport"</span> content<span class="op">=</span><span class="str">"width=device-width, initial-scale=1.0"</span><span class="op">&gt;</span>
  <span class="op">&lt;</span><span class="kw">title</span><span class="op">&gt;</span>Vuln App<span class="op">&lt;/</span><span class="kw">title</span><span class="op">&gt;</span>
  <span class="op">&lt;</span><span class="kw">link</span> rel<span class="op">=</span><span class="str">"stylesheet"</span> href<span class="op">=</span><span class="str">"/css/style.css"</span><span class="op">&gt;</span>
<span class="op">&lt;/</span><span class="kw">head</span><span class="op">&gt;</span>
<span class="op">&lt;</span><span class="kw">body</span><span class="op">&gt;</span>
  <span class="op">&lt;</span><span class="kw">nav</span><span class="op">&gt;</span>
    <span class="op">&lt;</span><span class="kw">a</span> href<span class="op">=</span><span class="str">"/"</span><span class="op">&gt;</span>Home<span class="op">&lt;/</span><span class="kw">a</span><span class="op">&gt;</span>
    <span class="op">&lt;</span><span class="kw">a</span> href<span class="op">=</span><span class="str">"/search"</span><span class="op">&gt;</span>Search<span class="op">&lt;/</span><span class="kw">a</span><span class="op">&gt;</span>
    <span class="cmt">&lt;%</span> <span class="kw">if</span> (user) { <span class="cmt">%&gt;</span>
      <span class="op">&lt;</span><span class="kw">a</span> href<span class="op">=</span><span class="str">"/profile"</span><span class="op">&gt;</span>Profile<span class="op">&lt;/</span><span class="kw">a</span><span class="op">&gt;</span>
      <span class="op">&lt;</span><span class="kw">a</span> href<span class="op">=</span><span class="str">"/logout"</span><span class="op">&gt;</span>Logout<span class="op">&lt;/</span><span class="kw">a</span><span class="op">&gt;</span>
    <span class="cmt">&lt;%</span> } <span class="kw">else</span> { <span class="cmt">%&gt;</span>
      <span class="op">&lt;</span><span class="kw">a</span> href<span class="op">=</span><span class="str">"/login"</span><span class="op">&gt;</span>Login<span class="op">&lt;/</span><span class="kw">a</span><span class="op">&gt;</span>
    <span class="cmt">&lt;%</span> } <span class="cmt">%&gt;</span>
  <span class="op">&lt;/</span><span class="kw">nav</span><span class="op">&gt;</span>

  <span class="op">&lt;</span><span class="kw">main</span><span class="op">&gt;</span>
    <span class="op">&lt;</span><span class="kw">h1</span><span class="op">&gt;</span>Vuln App<span class="op">&lt;/</span><span class="kw">h1</span><span class="op">&gt;</span>
    <span class="cmt">&lt;%</span> <span class="kw">if</span> (user) { <span class="cmt">%&gt;</span>
      <span class="op">&lt;</span><span class="kw">p</span><span class="op">&gt;</span>Welcome back, <span class="cmt">&lt;%-</span> user.username <span class="cmt">%&gt;</span>!<span class="op">&lt;/</span><span class="kw">p</span><span class="op">&gt;</span>
    <span class="cmt">&lt;%</span> } <span class="kw">else</span> { <span class="cmt">%&gt;</span>
      <span class="op">&lt;</span><span class="kw">p</span><span class="op">&gt;</span>Please <span class="op">&lt;</span><span class="kw">a</span> href<span class="op">=</span><span class="str">"/login"</span><span class="op">&gt;</span>log in<span class="op">&lt;/</span><span class="kw">a</span><span class="op">&gt;</span> to continue.<span class="op">&lt;/</span><span class="kw">p</span><span class="op">&gt;</span>
    <span class="cmt">&lt;%</span> } <span class="cmt">%&gt;</span>
  <span class="op">&lt;/</span><span class="kw">main</span><span class="op">&gt;</span>
<span class="op">&lt;/</span><span class="kw">body</span><span class="op">&gt;</span>
<span class="op">&lt;/</span><span class="kw">html</span><span class="op">&gt;</span></pre>
    </div>

    <p>
      Notice two things that are intentionally vulnerable in this template:
    </p>

    <ul>
      <li><strong><code>&lt;%- user.username %&gt;</code> (unescaped output):</strong> The <code>&lt;%-</code> tag
        outputs raw HTML without escaping. If a username contains <code>&lt;script&gt;</code> tags, they will execute.
        The safe version is <code>&lt;%= %&gt;</code> which HTML-encodes the output. We use the dangerous version
        here because this exact pattern is how Stored XSS happens — you will exploit it in Lab 03.</li>
      <li><strong>No CSP meta tag:</strong> There is no Content-Security-Policy header or meta tag, so the browser
        will execute any inline script that gets injected.</li>
    </ul>
  </div>
</div>

<hr>

<h2>Running the Application</h2>

<div class="step">
  <div class="step-label">6</div>
  <div>
    <strong>Add a start script and install nodemon</strong>
    <p>
      We will use <code>nodemon</code> to automatically restart the server when files change. This saves you
      from manually restarting Node.js every time you edit code, which you will be doing constantly.
    </p>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">Terminal</span>
        <button class="code-copy">Copy</button>
      </div>
      <pre>npm install --save-dev nodemon</pre>
    </div>
    <p>
      Add this to the <code>"scripts"</code> section of your <code>package.json</code>:
    </p>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">package.json (partial)</span>
        <button class="code-copy">Copy</button>
      </div>
      <pre><span class="str">"scripts"</span>: {
  <span class="str">"start"</span>: <span class="str">"node app.js"</span>,
  <span class="str">"dev"</span>: <span class="str">"nodemon app.js"</span>
}</pre>
    </div>
  </div>
</div>

<div class="step">
  <div class="step-label">7</div>
  <div>
    <strong>Initialize the database and start the server</strong>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">Terminal</span>
        <button class="code-copy">Copy</button>
      </div>
      <pre>node db/init.js        <span class="cmt"># Creates app.db with schema + seed data</span>
npm run dev            <span class="cmt"># Starts the server with auto-restart</span></pre>
    </div>
    <p>
      If everything is set up correctly, you should see:
    </p>
    <div class="code-block">
      <div class="code-header">
        <span class="code-file">Terminal Output</span>
        <button class="code-copy">Copy</button>
      </div>
      <pre>Database initialized with seed data.
Server running on http://localhost:3000</pre>
    </div>
    <p>
      Open <strong>http://localhost:3000</strong> in your browser. You should see the index page. It will not
      look like much yet -- and that is fine. The fun starts in the next lab, where you will add a login
      form and immediately break it with SQL injection.
    </p>
  </div>
</div>

<div class="callout info">
  <div class="callout-title">Troubleshooting</div>
  <div class="callout-text">
    If <code>better-sqlite3</code> fails to install, you likely need build tools. On macOS, run
    <code>xcode-select --install</code>. On Ubuntu, run <code>sudo apt install build-essential</code>.
    On Windows, install the Visual Studio Build Tools with the "Desktop development with C++" workload.
    If MongoDB refuses to connect, make sure the <code>mongod</code> service is running. On macOS with
    Homebrew: <code>brew services start mongodb-community</code>. On Ubuntu:
    <code>sudo systemctl start mongod</code>.
  </div>
</div>

<hr>

<h2>What Happens Next</h2>

<p>
  You now have a working (and deliberately insecure) Express application with a seeded database full of
  plaintext passwords, an unprotected session configuration, and zero security headers. Congratulations --
  you have built a target.
</p>

<p>
  In the next lab, you will add a login form and a search feature to this application. Both will be
  vulnerable to SQL injection. You will exploit them, extract data you were never meant to see, and then
  fix the code with parameterized queries. It is the first time you will feel the difference between
  knowing about a vulnerability and actually exploiting one. Let us get to it.
</p>

<div class="section-nav">
  <button class="nav-btn" data-prev="intro">Previous: Introduction</button>
  <button class="nav-btn" data-next="sqli">Next: SQL Injection</button>
</div>

`;
