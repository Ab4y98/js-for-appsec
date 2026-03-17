window.LESSONS = window.LESSONS || {};
window.LESSONS.path = `

<h1 class="lesson-title">Lab 11: Path Traversal</h1>

<p class="lesson-subtitle">
  How <code>../</code> in a filename lets an attacker read any file on your server, and why input filtering
  alone will never be enough to stop it.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> Build a File Download Endpoint</h2>

<p>
  Here is a completely normal feature request: your application lets users upload files, and now they need
  an endpoint to download them. The uploads live in a specific directory on the server, and you build a
  route that takes a filename as a query parameter and serves the corresponding file. This is bread-and-butter
  web development. Every application that handles user files has something like this.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/files.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> express = <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> path = <span class="fn">require</span>(<span class="str">'path'</span>);
<span class="kw">const</span> router = express.<span class="fn">Router</span>();

<span class="kw">const</span> UPLOADS_DIR = path.<span class="fn">join</span>(__dirname, <span class="str">'../uploads'</span>);

<span class="cmt">// Download a file by name</span>
router.<span class="fn">get</span>(<span class="str">'/files/download'</span>, (req, res) => {
  <span class="kw">const</span> fileName = req.query.name;
  <span class="kw">const</span> filePath = path.<span class="fn">join</span>(UPLOADS_DIR, fileName);
  res.<span class="fn">sendFile</span>(filePath);
});
  </pre>
</div>

<p>
  Look at that code carefully. The server takes the <code>name</code> query parameter directly from the
  request and joins it with the uploads directory path. Then it sends whatever file that path points to.
  The intention is clear: the user asks for <code>report.pdf</code>, and the server serves
  <code>/app/uploads/report.pdf</code>. Clean and simple.
</p>

<p>
  But what if the user does not send <code>report.pdf</code>? What if they send <code>../../etc/passwd</code>?
  That is the entire premise of path traversal, and it is one of the oldest vulnerability classes in web
  security. The server is supposed to serve files from one specific directory, but by manipulating the
  filename, the attacker can escape that directory and read arbitrary files from anywhere on the filesystem.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Basic Path Traversal</h2>

<p>
  The <code>..</code> sequence in a file path means "go up one directory." You use it all the time in
  your own terminal -- <code>cd ..</code> moves you one level up. When you chain multiple <code>../</code>
  sequences together, you climb further and further up the directory tree. Stack enough of them and you
  reach the filesystem root, from which you can navigate to any file on the system.
</p>

<p>
  Let me show you exactly what happens with a traversal payload:
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">path-resolution.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> path = <span class="fn">require</span>(<span class="str">'path'</span>);

<span class="cmt">// What the developer expects</span>
path.<span class="fn">join</span>(<span class="str">'/app/uploads'</span>, <span class="str">'report.pdf'</span>);
<span class="cmt">// => '/app/uploads/report.pdf'  -- inside the uploads directory</span>

<span class="cmt">// What the attacker sends</span>
path.<span class="fn">join</span>(<span class="str">'/app/uploads'</span>, <span class="str">'../../etc/passwd'</span>);
<span class="cmt">// => '/etc/passwd'  -- completely outside the uploads directory</span>

<span class="cmt">// How the resolution works step by step:</span>
<span class="cmt">// Start:  /app/uploads</span>
<span class="cmt">// ..   => /app          (up one level)</span>
<span class="cmt">// ..   => /             (up another level, now at root)</span>
<span class="cmt">// etc  => /etc</span>
<span class="cmt">// passwd => /etc/passwd  (attacker reads the password file)</span>
  </pre>
</div>

<div class="attack-box">
  <div class="attack-box-title">Path Traversal Attack</div>
  <pre>
# Read the system password file
curl "http://localhost:3000/files/download?name=../../etc/passwd"

# Read the application's environment variables (often contains secrets)
curl "http://localhost:3000/files/download?name=../../app/.env"

# Read the application source code
curl "http://localhost:3000/files/download?name=../../app/routes/auth.js"

# On a real server, the attacker would try:
# /etc/shadow (password hashes), SSH keys, database credentials,
# cloud provider metadata endpoints, and more
  </pre>
</div>

<p>
  This is not a subtle attack. The attacker is literally typing <code>../</code> in a URL parameter. And
  yet this vulnerability appears in production applications with alarming frequency because the code that
  creates it looks completely normal. The developer wrote <code class="fn">path.join</code> and
  <code class="fn">res.sendFile</code> -- two standard, well-known Node.js functions. Nothing about the
  code screams "vulnerability" unless you are specifically thinking about what happens when the filename
  is not what you expect.
</p>

<p>
  That is what makes path traversal insidious. The vulnerable code is indistinguishable from correct code
  at a glance. It only breaks when you consider adversarial input.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> Bypassing Simple Filters</h2>

<p>
  I can already hear you thinking: "I will just check for <code>../</code> in the input and reject it."
  Let me show you why that approach fails. Attackers have been bypassing naive path traversal filters for
  decades, and they have accumulated a substantial bag of tricks.
</p>

<h3>Double Encoding</h3>

<p>
  URL encoding represents characters as percent-encoded hex values. The forward slash <code>/</code>
  becomes <code>%2F</code>, and the dot <code>.</code> becomes <code>%2E</code>. If your filter checks
  the raw query string for <code>../</code>, the attacker can send <code>..%2F..%2Fetc%2Fpasswd</code>
  instead. Your filter does not see <code>../</code> because it is encoded. But the web server decodes
  the percent-encoding <em>after</em> your filter runs, and the path resolves exactly the same way.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">encoding-bypass.sh</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt"># Basic traversal -- caught by naive filter</span>
<span class="fn">curl</span> <span class="str">"http://localhost:3000/files/download?name=../../etc/passwd"</span>

<span class="cmt"># URL-encoded slashes -- bypasses string matching on "../"</span>
<span class="fn">curl</span> <span class="str">"http://localhost:3000/files/download?name=..%2F..%2Fetc%2Fpasswd"</span>

<span class="cmt"># Double-encoded -- %252F decodes to %2F, then to /</span>
<span class="fn">curl</span> <span class="str">"http://localhost:3000/files/download?name=..%252F..%252Fetc%252Fpasswd"</span>
  </pre>
</div>

<h3>Null Byte Injection</h3>

<p>
  In older versions of Node.js (and many other languages), the null byte <code>%00</code> has a special
  property: when the string is passed to the operating system for file operations, the OS treats the
  null byte as the end of the string. So an attacker can send
  <code>../../etc/passwd%00.pdf</code>. Your server-side filter sees that the filename ends with
  <code>.pdf</code> and allows it. But when the OS opens the file, it sees
  <code>../../etc/passwd</code> followed by a null byte and ignores everything after it. The extension
  check passes, but the file that gets read is <code>/etc/passwd</code>.
</p>

<p>
  Modern Node.js versions (v8.5+ with the fix for CVE-2017-14849 and later hardening) reject paths
  containing null bytes, so this specific trick is less relevant today. But I want you to understand
  the principle: there are many layers of string processing between the user's input and the actual
  file operation, and each layer is an opportunity for an attacker to slip past your filter.
</p>

<h3>Backslash on Windows</h3>

<p>
  If your application runs on Windows, you have an additional concern: Windows accepts both forward
  slashes and backslashes as path separators. An attacker can send <code>..\\..\\..\\windows\\system.ini</code>
  and your filter that only checks for <code>../</code> will miss it entirely. Node.js on Windows
  normalizes both separators, so the path resolves correctly from the attacker's perspective.
</p>

<h3>Unicode Normalization</h3>

<p>
  Some systems perform Unicode normalization on filenames. Certain Unicode characters can normalize to
  dots or slashes in ways that bypass string-based filters. For example, the fullwidth full stop
  (U+FF0E) might normalize to a regular dot (U+002E) on certain filesystems or web servers. These
  attacks are more exotic, but they illustrate the fundamental problem: <strong>you cannot enumerate
  all possible representations of a path traversal sequence</strong>. Filtering is a losing game
  because you are trying to build a blocklist against an attacker who only needs to find one
  representation you missed.
</p>

<div class="callout warn">
  <div class="callout-title">Why Filtering Fails</div>
  <div class="callout-text">
    Every filter-based approach to path traversal is playing whack-a-mole. You block <code>../</code>,
    the attacker uses <code>%2E%2E%2F</code>. You block that, they use double encoding. You block
    that, they use backslashes. The right approach is not to filter malicious input -- it is to
    validate the <em>result</em> after all path resolution has happened.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> The Fix -- Canonicalization + Prefix Check</h2>

<p>
  The correct defense against path traversal does not try to detect malicious input patterns. Instead,
  it lets the path resolve completely and then checks whether the final, canonical path is still inside
  the allowed directory. This approach is immune to encoding tricks, backslash variations, and Unicode
  normalization because it operates on the <em>result</em> of all those transformations, not on the raw
  input.
</p>

<div class="fix-box">
  <div class="fix-box-title">Secure File Download Endpoint</div>
  <pre>
<span class="kw">const</span> express = <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> path = <span class="fn">require</span>(<span class="str">'path'</span>);
<span class="kw">const</span> router = express.<span class="fn">Router</span>();

<span class="kw">const</span> UPLOADS_DIR = path.<span class="fn">resolve</span>(__dirname, <span class="str">'../uploads'</span>);

router.<span class="fn">get</span>(<span class="str">'/files/download'</span>, (req, res) => {
  <span class="kw">const</span> fileName = req.query.name;

  <span class="kw">if</span> (!fileName) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">400</span>).<span class="fn">json</span>({ error: <span class="str">'File name is required'</span> });
  }

  <span class="cmt">// Step 1: Resolve to an absolute, canonical path</span>
  <span class="cmt">// This collapses ALL ../ sequences, resolves symlinks,</span>
  <span class="cmt">// normalizes slashes, and gives you the REAL final path</span>
  <span class="kw">const</span> resolved = path.<span class="fn">resolve</span>(UPLOADS_DIR, fileName);

  <span class="cmt">// Step 2: Check that the resolved path is still inside UPLOADS_DIR</span>
  <span class="cmt">// If the attacker used ../ to escape, the resolved path will</span>
  <span class="cmt">// NOT start with UPLOADS_DIR</span>
  <span class="kw">if</span> (!resolved.<span class="fn">startsWith</span>(UPLOADS_DIR + path.sep)) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">403</span>).<span class="fn">json</span>({ error: <span class="str">'Access denied'</span> });
  }

  <span class="cmt">// Step 3: Serve the file -- we know it is inside the allowed directory</span>
  res.<span class="fn">sendFile</span>(resolved);
});
  </pre>
</div>

<p>
  Let me walk through why this works. <code class="fn">path.resolve()</code> takes whatever path you give
  it -- including all the <code>../</code> sequences, encoded characters, backslashes, and any other tricks --
  and computes the final absolute path after all traversal is applied. It gives you the real, canonical
  location on the filesystem. Then <code class="fn">startsWith()</code> checks whether that real location
  is inside the uploads directory.
</p>

<p>
  If the attacker sends <code>../../etc/passwd</code>, <code class="fn">path.resolve()</code> computes
  <code>/etc/passwd</code>. That does not start with <code>/app/uploads/</code>. Rejected. It does not
  matter how the attacker encoded the traversal sequences or what tricks they used, because we are not
  inspecting the input -- we are inspecting the output after the path is fully resolved.
</p>

<div class="callout info">
  <div class="callout-title">Why path.sep Matters</div>
  <div class="callout-text">
    Notice we check <code>resolved.startsWith(UPLOADS_DIR + path.sep)</code> with the trailing
    separator, not just <code>resolved.startsWith(UPLOADS_DIR)</code>. Without the trailing separator,
    a directory called <code>/app/uploads-backup</code> would also pass the check since it starts
    with <code>/app/uploads</code>. The trailing separator ensures we are inside the directory, not
    just matching a prefix of a different directory name.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> Zip Slip -- Path Traversal in Archives</h2>

<p>
  Path traversal does not only happen through URL parameters. One of the most dangerous variants occurs
  during archive extraction, and it has its own name: Zip Slip.
</p>

<p>
  Here is the scenario. Your application accepts ZIP file uploads -- maybe users upload bundles of
  documents, or your deployment pipeline extracts configuration archives. When you extract the ZIP file,
  you iterate over each entry and write it to a directory. But a malicious ZIP file can contain entries
  with paths like <code>../../../etc/cron.d/backdoor</code>. When your extraction code naively joins
  the target directory with the entry's filename and writes the file, it lands outside the intended
  directory. The attacker has written an arbitrary file to an arbitrary location on your filesystem.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">vulnerable-extraction.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> AdmZip = <span class="fn">require</span>(<span class="str">'adm-zip'</span>);
<span class="kw">const</span> path = <span class="fn">require</span>(<span class="str">'path'</span>);

<span class="kw">const</span> EXTRACT_DIR = <span class="str">'/app/extracted'</span>;

<span class="cmt">// VULNERABLE: does not validate entry paths</span>
<span class="kw">function</span> <span class="fn">extractZip</span>(zipPath) {
  <span class="kw">const</span> zip = <span class="kw">new</span> <span class="fn">AdmZip</span>(zipPath);
  <span class="kw">const</span> entries = zip.<span class="fn">getEntries</span>();

  entries.<span class="fn">forEach</span>((entry) => {
    <span class="kw">const</span> outputPath = path.<span class="fn">join</span>(EXTRACT_DIR, entry.entryName);
    <span class="cmt">// If entry.entryName is "../../../etc/cron.d/backdoor",</span>
    <span class="cmt">// outputPath resolves to /etc/cron.d/backdoor</span>
    zip.<span class="fn">extractEntryTo</span>(entry, outputPath);
  });
}
  </pre>
</div>

<p>
  This is the exact same vulnerability as the URL-based path traversal, just triggered by a different
  input vector. Instead of manipulating a query parameter, the attacker manipulates file paths inside
  an archive. ZIP, TAR, RAR, 7z -- any archive format that stores relative paths in its entries is
  susceptible to this attack.
</p>

<p>
  The fix is identical in principle: resolve the output path to its canonical form and verify it stays
  inside the target directory before writing.
</p>

<div class="fix-box">
  <div class="fix-box-title">Safe Archive Extraction</div>
  <pre>
<span class="kw">function</span> <span class="fn">extractZipSafe</span>(zipPath) {
  <span class="kw">const</span> zip = <span class="kw">new</span> <span class="fn">AdmZip</span>(zipPath);
  <span class="kw">const</span> entries = zip.<span class="fn">getEntries</span>();
  <span class="kw">const</span> resolvedBase = path.<span class="fn">resolve</span>(EXTRACT_DIR);

  entries.<span class="fn">forEach</span>((entry) => {
    <span class="kw">const</span> outputPath = path.<span class="fn">resolve</span>(EXTRACT_DIR, entry.entryName);

    <span class="cmt">// Validate EVERY entry's resolved path</span>
    <span class="kw">if</span> (!outputPath.<span class="fn">startsWith</span>(resolvedBase + path.sep)) {
      <span class="kw">throw new</span> <span class="fn">Error</span>(
        <span class="str">\`Zip Slip detected: \${entry.entryName} escapes target directory\`</span>
      );
    }

    zip.<span class="fn">extractEntryTo</span>(entry, EXTRACT_DIR, <span class="kw">true</span>, <span class="kw">true</span>);
  });
}
  </pre>
</div>

<div class="callout warn">
  <div class="callout-title">Zip Slip Is Widespread</div>
  <div class="callout-text">
    When the Snyk security team published their research on Zip Slip, they found the vulnerability
    in libraries and applications across virtually every programming language. Many popular archive
    extraction libraries did not validate entry paths by default. If your application extracts
    user-uploaded archives, check whether your extraction library performs this validation
    automatically. If it does not, you must do it yourself.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> Defense Beyond Path Checks</h2>

<p>
  The canonicalization and prefix check I showed you is the primary defense, and it is effective. But
  a mature security posture goes further. Let me walk you through additional layers that defense-in-depth
  demands.
</p>

<h3>Chroot and Filesystem Jails</h3>

<p>
  A chroot jail restricts a process's view of the filesystem so that a particular directory appears to
  be the root. If your file-serving process runs in a chroot rooted at <code>/app/uploads</code>, then
  even a successful path traversal cannot reach <code>/etc/passwd</code> because, from the process's
  perspective, <code>/etc/passwd</code> does not exist. The process literally cannot see files outside
  its jail. Containers (Docker, etc.) provide a similar filesystem isolation effect. If your application
  runs in a container, the attack surface of a path traversal is limited to the files visible inside
  the container.
</p>

<h3>Symlink Following</h3>

<p>
  Here is a subtle edge case that trips people up. You have implemented the resolve-and-check defense,
  and the resolved path is inside the uploads directory. But what if that file is a symbolic link that
  points to <code>/etc/passwd</code>? The path check passes -- the symlink itself is inside the allowed
  directory -- but the file that gets served is outside it.
</p>

<p>
  To handle this, use <code class="fn">fs.lstat()</code> (not <code class="fn">fs.stat()</code>) to
  check whether the file is a symlink before serving it. <code class="fn">lstat()</code> reports on
  the link itself, while <code class="fn">stat()</code> follows the link and reports on the target.
  If <code class="fn">lstat()</code> indicates a symlink, reject the request. Alternatively, use
  <code class="fn">fs.realpath()</code> to resolve symlinks before doing the prefix check -- this
  gives you the final physical path after both <code>../</code> resolution and symlink resolution.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">symlink-safe.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> fs = <span class="fn">require</span>(<span class="str">'fs'</span>);
<span class="kw">const</span> path = <span class="fn">require</span>(<span class="str">'path'</span>);

<span class="kw">async function</span> <span class="fn">safeServFile</span>(uploadsDir, fileName) {
  <span class="kw">const</span> resolved = path.<span class="fn">resolve</span>(uploadsDir, fileName);

  <span class="cmt">// First check: path must be inside uploads dir</span>
  <span class="kw">if</span> (!resolved.<span class="fn">startsWith</span>(uploadsDir + path.sep)) {
    <span class="kw">throw new</span> <span class="fn">Error</span>(<span class="str">'Path traversal detected'</span>);
  }

  <span class="cmt">// Second check: resolve symlinks and verify AGAIN</span>
  <span class="kw">const</span> realPath = <span class="kw">await</span> fs.promises.<span class="fn">realpath</span>(resolved);
  <span class="kw">if</span> (!realPath.<span class="fn">startsWith</span>(uploadsDir + path.sep)) {
    <span class="kw">throw new</span> <span class="fn">Error</span>(<span class="str">'Symlink escape detected'</span>);
  }

  <span class="kw">return</span> realPath;
}
  </pre>
</div>

<h3>Principle of Least Privilege</h3>

<p>
  Even with perfect path validation, you should ask yourself: why does the Node.js process have read
  access to <code>/etc/passwd</code> in the first place? If the application only needs to read files
  from the uploads directory, run the process under a user account that only has read access to that
  directory. On Linux, this means creating a dedicated service user with restricted permissions. In a
  container, this means not running as root (which is the default in many Docker setups, and a terrible
  practice).
</p>

<p>
  Least privilege does not prevent the vulnerability, but it limits the damage when the vulnerability
  is exploited. If the process cannot read <code>/etc/shadow</code> or the application's
  <code>.env</code> file because the OS-level permissions forbid it, then a successful path traversal
  returns "access denied" instead of sensitive data. That is a meaningful difference.
</p>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> Route Parameter Traversal</h2>

<p>
  Most developers think of path traversal as a query-parameter problem: <code>?file=../../etc/passwd</code>.
  But the same vulnerability appears in route parameters, and it is even easier to miss because the
  traversal payload is embedded in the URL path itself, not a named parameter.
</p>

<div class="attack-box">
  <div class="attack-box-title">Attack: Path Traversal via Route Parameters</div>
  <pre>
<span class="cmt"># The endpoint expects a username in the URL path</span>
<span class="cmt"># GET /api/users/:username/avatar</span>

<span class="cmt"># Normal usage:</span>
curl http://localhost:3000/api/users/alice/avatar

<span class="cmt"># But what if the username IS the traversal payload?</span>
curl http://localhost:3000/api/users/..%2F..%2F..%2Fetc%2Fpasswd/avatar

<span class="cmt"># Or using the path directly:</span>
curl http://localhost:3000/api/users/../../../etc/passwd%00/avatar

<span class="cmt"># The server builds: AVATARS_DIR + "/../../../etc/passwd" + ".png"</span>
<span class="cmt"># path.join resolves to /etc/passwd.png (or without extension</span>
<span class="cmt"># if the code reads the raw parameter)</span>
  </pre>
</div>

<p>
  This is dangerous because developers often validate query parameters but forget that route
  parameters are equally attacker-controlled. Express does not sanitize <code>req.params</code>
  any more than it sanitizes <code>req.query</code>. The fix is the same: canonicalize with
  <code>path.resolve()</code>, then verify the resolved path starts with your intended directory.
  Apply this check to every file-system operation, regardless of where the input comes from.
</p>

<div class="callout warn">
  <div class="callout-title">Every Input Is an Attack Surface</div>
  <div class="callout-text">
    Path traversal can come through query parameters (<code>?file=</code>), route parameters
    (<code>/:username/</code>), POST body fields, HTTP headers (Content-Disposition), or even
    filenames in multipart uploads. If any user-controlled value touches a filesystem path,
    validate it. The same <code>path.resolve() + startsWith()</code> pattern works for all of them.
  </div>
</div>

<hr>

<h2>Lab Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Build the file download endpoint with <code>path.join(UPLOADS_DIR, fileName)</code> and confirm it serves files from the uploads directory</li>
  <li><span class="task-check"></span> Exploit it with <code>../../etc/passwd</code> to read a file outside the uploads directory and verify the contents are returned</li>
  <li><span class="task-check"></span> Attempt the bypass techniques: URL-encoded slashes (<code>%2F</code>), double encoding (<code>%252F</code>), and backslash sequences on Windows</li>
  <li><span class="task-check"></span> Exploit path traversal through a route parameter (e.g., username in <code>/api/users/:username/avatar</code>)</li>
  <li><span class="task-check"></span> Implement the fix using <code>path.resolve()</code> and <code>startsWith()</code> to canonicalize the path and verify it stays inside the allowed directory</li>
  <li><span class="task-check"></span> Add symlink protection using <code>fs.realpath()</code> and verify that a symlink pointing outside the uploads directory is rejected</li>
  <li><span class="task-check"></span> Create a malicious ZIP file with a traversal entry name and verify your safe extraction code detects and rejects it</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="deser">Previous: Insecure Deserialization</button>
  <button class="nav-btn" data-next="regexdos">Next: ReDoS</button>
</div>

`;
