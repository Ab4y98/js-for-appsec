window.LESSONS = window.LESSONS || {};
window.LESSONS.idor = `

<h1 class="lesson-title">Lab 08: Insecure Direct Object References</h1>

<p class="lesson-subtitle">
  The simplest authorization bug in existence, and somehow still one of the most common.
  You will build an API that forgets to ask "does this user own this resource?"
  and then watch an attacker walk through every record in your database.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 1</span> Build the Vulnerable Endpoint</h2>

<p>
  Let me walk you through what might be the most common vulnerability I have seen in production APIs.
  It is deceptively simple, and that is exactly why it slips through code review so easily. We are going
  to build a notes API where each note belongs to a specific user, and the endpoint to fetch a note does
  not bother checking whether the requesting user actually owns it.
</p>

<p>
  First, let us seed the database. We want notes belonging to several users, and critically, we want one
  note belonging to an admin user that contains something sensitive -- an API key. This is not contrived.
  I have personally found admin API keys stored in internal notes, configuration records, and "scratch pad"
  features in production applications more times than I care to admit.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">seed.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="kw">const</span> db <span class="op">=</span> <span class="fn">require</span>(<span class="str">'./db'</span>);

<span class="cmt">// Seed notes for different users</span>
db.<span class="fn">run</span>(<span class="str">\`INSERT INTO notes (id, user_id, title, body) VALUES
  (1, 1, 'Grocery List', 'Milk, eggs, bread'),
  (2, 1, 'Meeting Notes', 'Discuss Q3 roadmap'),
  (3, 2, 'Vacation Plans', 'Book flights to Lisbon'),
  (4, 3, 'Project Ideas', 'Build a CLI tool for log analysis'),
  (5, 99, 'Admin Config', 'API_KEY=sk-live-9f8a7b6c5d4e3f2a1b0c')\`</span>);
  </pre>
</div>

<p>
  Now the vulnerable route. This is the kind of code that looks completely normal at first glance. It takes
  an ID from the URL, queries the database, and returns the note. What could possibly be wrong?
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/notes.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// GET /api/notes/:id -- fetch a note by ID</span>
router.<span class="fn">get</span>(<span class="str">'/api/notes/:id'</span>, <span class="fn">requireAuth</span>, (<span class="kw">req</span>, <span class="kw">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> noteId <span class="op">=</span> req.params.id;

  db.<span class="fn">get</span>(<span class="str">'SELECT * FROM notes WHERE id = ?'</span>, [noteId], (err, note) <span class="op">=></span> {
    <span class="kw">if</span> (err) <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">500</span>).<span class="fn">json</span>({ error: <span class="str">'Database error'</span> });
    <span class="kw">if</span> (!note) <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">404</span>).<span class="fn">json</span>({ error: <span class="str">'Note not found'</span> });

    <span class="cmt">// BUG: No ownership check. Any authenticated user can read any note.</span>
    res.<span class="fn">json</span>(note);
  });
});
  </pre>
</div>

<p>
  Here is the core concept I want you to internalize. This route uses <code>requireAuth</code> middleware,
  so the server knows <em>who</em> is making the request. It has solved authentication. But it has completely
  skipped authorization. Authentication answers "who are you?" Authorization answers "are you allowed to do
  this?" They are two entirely different questions, and an enormous number of production APIs answer the first
  one correctly while ignoring the second one entirely.
</p>

<div class="callout warn">
  <div class="callout-title">The Core Distinction</div>
  <div class="callout-text">
    Authentication verifies identity. Authorization verifies permission. Your endpoint does the first
    and skips the second. That gap is the entire vulnerability.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 2</span> Exploitation -- ID Enumeration</h2>

<p>
  Now let us put on the attacker hat. You are logged in as user 2. You can legitimately access note 3,
  which belongs to you. But what happens if you just... change the number in the URL? This is not a
  sophisticated attack. It requires zero tools, zero expertise, and about three seconds of curiosity.
</p>

<div class="attack-box">
  <div class="attack-box-title">Attack: Manual Enumeration via curl</div>
  <pre>
<span class="cmt"># Fetch your own note -- this is legitimate</span>
curl -b <span class="str">"session=YOUR_SESSION_COOKIE"</span> http://localhost:3000/api/notes/3

<span class="cmt"># Now try someone else's note</span>
curl -b <span class="str">"session=YOUR_SESSION_COOKIE"</span> http://localhost:3000/api/notes/1

<span class="cmt"># And the admin note with the API key</span>
curl -b <span class="str">"session=YOUR_SESSION_COOKIE"</span> http://localhost:3000/api/notes/5
  </pre>
</div>

<p>
  That is it. You just accessed another user's grocery list, their meeting notes, and an admin API key.
  No SQL injection. No XSS. No buffer overflow. You changed a number from 3 to 5. The server happily
  handed you data you were never supposed to see.
</p>

<p>
  Now let us automate it. An attacker is not going to stop at guessing a few IDs. They are going to
  enumerate every single record in the table.
</p>

<div class="attack-box">
  <div class="attack-box-title">Attack: Automated ID Enumeration Script</div>
  <pre>
<span class="cmt">// enumerate.js -- harvest every note in the database</span>
<span class="kw">const</span> SESSION <span class="op">=</span> <span class="str">'YOUR_SESSION_COOKIE'</span>;

<span class="kw">for</span> (<span class="kw">let</span> id <span class="op">=</span> <span class="num">1</span>; id <span class="op">&lt;=</span> <span class="num">100</span>; id<span class="op">++</span>) {
  <span class="fn">fetch</span>(<span class="str">\`http://localhost:3000/api/notes/\${id}\`</span>, {
    headers: { <span class="str">'Cookie'</span>: <span class="str">\`session=\${SESSION}\`</span> }
  })
  .<span class="fn">then</span>(r <span class="op">=></span> r.<span class="fn">json</span>())
  .<span class="fn">then</span>(data <span class="op">=></span> {
    <span class="kw">if</span> (!data.error) {
      console.<span class="fn">log</span>(<span class="str">\`[ID \${id}] User \${data.user_id}: \${data.title}\`</span>);
      console.<span class="fn">log</span>(<span class="str">\`  Body: \${data.body}\`</span>);
    }
  });
}
  </pre>
</div>

<p>
  Sequential integer IDs make this trivially easy. The attacker does not need to guess or discover anything.
  They just count. Start at 1, go to some large number, and collect everything the server gives back. It is
  like leaving every filing cabinet in your office unlocked and numbered sequentially. Anyone who walks in
  just has to open them one by one.
</p>

<div class="callout info">
  <div class="callout-title">Why Sequential IDs Are Dangerous</div>
  <div class="callout-text">
    Sequential integer IDs leak information by their very nature. An attacker can estimate how many records
    exist, when they were created (roughly), and systematically access every single one. The IDs themselves
    become an attack surface.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Step 3</span> Vertical Privilege Escalation</h2>

<p>
  So far we have been looking at what security folks call <strong>horizontal escalation</strong>: a regular
  user accessing another regular user's data. Both users are at the same privilege level. The attacker is
  moving sideways. But there is a nastier variant: <strong>vertical escalation</strong>, where a regular
  user accesses functionality reserved for admins or other higher-privilege roles.
</p>

<p>
  Consider this admin endpoint. It exists in more applications than you would expect, and the bug is
  exactly the same: authentication without authorization.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/admin.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// Admin endpoint: list all users and their roles</span>
router.<span class="fn">get</span>(<span class="str">'/api/admin/users'</span>, <span class="fn">requireAuth</span>, (<span class="kw">req</span>, <span class="kw">res</span>) <span class="op">=></span> {
  <span class="cmt">// BUG: checks if user is logged in, but NOT if user is an admin</span>
  db.<span class="fn">all</span>(<span class="str">'SELECT id, username, email, role FROM users'</span>, (err, users) <span class="op">=></span> {
    res.<span class="fn">json</span>(users);
  });
});

<span class="cmt">// Admin endpoint: delete any user</span>
router.<span class="fn">delete</span>(<span class="str">'/api/admin/users/:id'</span>, <span class="fn">requireAuth</span>, (<span class="kw">req</span>, <span class="kw">res</span>) <span class="op">=></span> {
  <span class="cmt">// BUG: same problem. Any authenticated user can delete anyone.</span>
  db.<span class="fn">run</span>(<span class="str">'DELETE FROM users WHERE id = ?'</span>, [req.params.id], (err) <span class="op">=></span> {
    res.<span class="fn">json</span>({ message: <span class="str">'User deleted'</span> });
  });
});
  </pre>
</div>

<p>
  A regular user who discovers these endpoints -- through JavaScript source code, API documentation left
  publicly accessible, or simply guessing common paths like <code>/api/admin/*</code> -- can now list
  every user in the system and delete any account. That is vertical privilege escalation. You are not just
  reading a peer's data; you are performing admin actions without being an admin.
</p>

<p>
  The distinction matters because the impact is different. Horizontal escalation compromises individual users.
  Vertical escalation compromises the entire application. If an attacker can access admin functions, they
  effectively own the system.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 4</span> The Fix -- Ownership Checks</h2>

<p>
  The fix for IDOR is almost insultingly simple, which makes it even more frustrating that it gets missed
  so often. You need to verify that the authenticated user has permission to access the requested resource.
  There are two clean patterns for this.
</p>

<h3>Pattern 1: Query-Level Filtering</h3>

<p>
  The most robust approach is to include the user's ID directly in the database query. This way, if the
  note does not belong to the requesting user, the query returns nothing. There is no window where the
  data is fetched but not yet checked.
</p>

<div class="fix-box">
  <div class="fix-box-title">Fix: Add Ownership to the Query</div>
  <pre>
router.<span class="fn">get</span>(<span class="str">'/api/notes/:id'</span>, <span class="fn">requireAuth</span>, (<span class="kw">req</span>, <span class="kw">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> noteId <span class="op">=</span> req.params.id;
  <span class="kw">const</span> userId <span class="op">=</span> req.session.user.id;

  <span class="cmt">// Query includes user_id -- only returns notes owned by this user</span>
  db.<span class="fn">get</span>(
    <span class="str">'SELECT * FROM notes WHERE id = ? AND user_id = ?'</span>,
    [noteId, userId],
    (err, note) <span class="op">=></span> {
      <span class="kw">if</span> (!note) <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">404</span>).<span class="fn">json</span>({ error: <span class="str">'Note not found'</span> });
      res.<span class="fn">json</span>(note);
    }
  );
});
  </pre>
</div>

<h3>Pattern 2: Fetch Then Check</h3>

<p>
  Sometimes the query-level approach is not practical -- maybe the ownership relationship is complex, or
  you need to return different error codes for "not found" versus "not authorized." In that case, fetch
  the resource first, then check ownership before returning it.
</p>

<div class="fix-box">
  <div class="fix-box-title">Fix: Post-Fetch Ownership Check</div>
  <pre>
router.<span class="fn">get</span>(<span class="str">'/api/notes/:id'</span>, <span class="fn">requireAuth</span>, (<span class="kw">req</span>, <span class="kw">res</span>) <span class="op">=></span> {
  db.<span class="fn">get</span>(<span class="str">'SELECT * FROM notes WHERE id = ?'</span>, [req.params.id], (err, note) <span class="op">=></span> {
    <span class="kw">if</span> (!note) <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">404</span>).<span class="fn">json</span>({ error: <span class="str">'Not found'</span> });

    <span class="cmt">// Ownership check: does this note belong to the requesting user?</span>
    <span class="kw">if</span> (note.user_id <span class="op">!==</span> req.session.user.id) {
      <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">403</span>).<span class="fn">json</span>({ error: <span class="str">'Forbidden'</span> });
    }

    res.<span class="fn">json</span>(note);
  });
});
  </pre>
</div>

<h3>Fixing Admin Routes</h3>

<p>
  For admin resources, the pattern is the same concept but the check is different. Instead of verifying
  ownership, you verify role.
</p>

<div class="fix-box">
  <div class="fix-box-title">Fix: Role-Based Access for Admin Endpoints</div>
  <pre>
<span class="kw">function</span> <span class="fn">requireAdmin</span>(req, res, next) {
  <span class="kw">if</span> (!req.session.user <span class="op">||</span> req.session.user.role <span class="op">!==</span> <span class="str">'admin'</span>) {
    <span class="kw">return</span> res.<span class="fn">status</span>(<span class="num">403</span>).<span class="fn">json</span>({ error: <span class="str">'Admin access required'</span> });
  }
  <span class="fn">next</span>();
}

router.<span class="fn">get</span>(<span class="str">'/api/admin/users'</span>, <span class="fn">requireAuth</span>, <span class="fn">requireAdmin</span>, (<span class="kw">req</span>, <span class="kw">res</span>) <span class="op">=></span> {
  <span class="cmt">// Now only actual admins reach this handler</span>
  db.<span class="fn">all</span>(<span class="str">'SELECT id, username, email, role FROM users'</span>, (err, users) <span class="op">=></span> {
    res.<span class="fn">json</span>(users);
  });
});
  </pre>
</div>

<p>
  The fix is always the same pattern, whether you are protecting notes, files, admin panels, or any other
  resource: check ownership or permission before returning data or performing an action. The specific
  implementation varies, but the principle never does.
</p>

<hr>

<h2 class="step"><span class="step-label">Step 5</span> UUIDs Are Not Enough</h2>

<p>
  I need to address a misconception I hear constantly. "We switched from integer IDs to UUIDs, so IDOR
  is not a problem for us anymore." This is wrong, and I want you to understand exactly why.
</p>

<p>
  Replacing <code>/api/notes/5</code> with <code>/api/notes/a1b2c3d4-e5f6-7890-abcd-ef1234567890</code>
  makes blind enumeration impractical. An attacker cannot just count from 1 to 100 anymore. That is a
  real benefit, and I am not dismissing it. But it does not fix the underlying vulnerability. If an
  attacker obtains a UUID through any other channel -- server logs, HTTP Referer headers, a leaked URL
  in a support ticket, another vulnerability that leaks IDs, or even the application's own API responses
  -- the IDOR works exactly the same way. The attacker plugs the UUID into the request and gets data
  they should not have.
</p>

<div class="callout warn">
  <div class="callout-title">UUIDs Are Obscurity, Not Security</div>
  <div class="callout-text">
    A UUID makes the ID harder to guess, but it does not make the resource harder to access once
    the ID is known. Obscurity buys time. Authorization checks provide actual security. You need both.
  </div>
</div>

<h3>IDOR in File Uploads</h3>

<p>
  IDOR is not limited to database records. It shows up everywhere resources are identified by
  user-controllable values. File uploads are a classic example. Consider an application that stores
  uploaded files with predictable names.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/uploads.js</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// Serve uploaded files -- no ownership check</span>
router.<span class="fn">get</span>(<span class="str">'/uploads/:filename'</span>, <span class="fn">requireAuth</span>, (<span class="kw">req</span>, <span class="kw">res</span>) <span class="op">=></span> {
  <span class="kw">const</span> filePath <span class="op">=</span> path.<span class="fn">join</span>(__dirname, <span class="str">'../uploads'</span>, req.params.filename);
  <span class="cmt">// BUG: any authenticated user can download any uploaded file</span>
  res.<span class="fn">sendFile</span>(filePath);
});
  </pre>
</div>

<p>
  If filenames follow a pattern -- <code>user1_avatar.png</code>, <code>user2_avatar.png</code>, or
  timestamps like <code>1678901234_document.pdf</code> -- an attacker can enumerate them just like
  integer IDs. Even "random" filenames leak through Referer headers, API responses, or HTML source code.
</p>

<h3>IDOR in API Pagination</h3>

<p>
  Here is a subtler variant that catches a lot of developers off guard. Your individual note endpoint
  has proper authorization, but your list endpoint leaks IDs for resources the user should not know about.
</p>

<div class="code-block">
  <div class="code-header">
    <span class="code-file">routes/notes.js -- list endpoint</span>
    <button class="code-copy">Copy</button>
  </div>
  <pre>
<span class="cmt">// List "recent" notes -- accidentally includes all users' notes</span>
router.<span class="fn">get</span>(<span class="str">'/api/notes'</span>, <span class="fn">requireAuth</span>, (<span class="kw">req</span>, <span class="kw">res</span>) <span class="op">=></span> {
  db.<span class="fn">all</span>(<span class="str">'SELECT id, title, created_at FROM notes ORDER BY created_at DESC'</span>, (err, notes) <span class="op">=></span> {
    <span class="cmt">// BUG: returns IDs and titles of ALL notes, not just this user's</span>
    res.<span class="fn">json</span>(notes);
  });
});
  </pre>
</div>

<p>
  Even if the detail endpoint checks ownership, the list endpoint just handed the attacker every note ID
  and title in the system. They now know exactly which IDs to target and have a preview of the content.
  IDOR protection has to be consistent across every endpoint that touches the resource.
</p>

<hr>

<h2>Real-World Context</h2>

<p>
  IDOR is consistently one of the most reported vulnerability categories in bug bounty programs. It is
  not glamorous. It does not have a cool logo or a catchy name like Heartbleed or Spectre. But it accounts
  for a staggering volume of real-world data breaches. The reason is simple: it is easy to introduce and
  easy to miss in code review, especially in APIs where the front-end UI might hide the underlying
  request parameters from casual observation.
</p>

<p>
  Mobile applications are a particularly rich hunting ground for IDOR. The mobile app's UI might only show
  you your own data, creating the illusion of access control. But behind the scenes, it is making REST API
  calls with IDs in the request, and those IDs can be intercepted and modified with tools like Burp Suite
  or even the browser's developer tools if there is also a web interface.
</p>

<p>
  My testing strategy, and the one I want you to adopt, is straightforward: for every authenticated request
  your application makes, try changing the identifying parameter -- the ID, the filename, the username in
  the path. Log in as two different users and try to access each other's resources. This takes five minutes
  per endpoint and catches one of the most impactful vulnerability classes in existence.
</p>

<div class="callout info">
  <div class="callout-title">Testing Checklist for IDOR</div>
  <div class="callout-text">
    For every endpoint that returns user-specific data: (1) authenticate as User A, (2) note the resource
    IDs in the response, (3) authenticate as User B, (4) try to access User A's resources using those IDs.
    If it works, you have an IDOR. Do this for every CRUD operation -- read, update, and delete.
  </div>
</div>

<hr>

<h2 class="step"><span class="step-label">Deeper</span> Write and Delete IDOR</h2>

<p>
  Everything we have explored so far is read-based IDOR -- the attacker views data they should not see.
  But the same flaw applies to write and delete operations, and the consequences are far more severe.
  If an attacker can modify or destroy another user's data, you have moved from data exposure to data
  integrity compromise.
</p>

<div class="attack-box">
  <div class="attack-box-title">Attack: Deleting Another User's Notes</div>
  <pre>
<span class="cmt"># Logged in as user 2, deleting user 1's note</span>
curl -X DELETE \
  -b <span class="str">"session=USER2_SESSION"</span> \
  http://localhost:3000/api/notes/1

<span class="cmt"># Response: { "message": "Note deleted" }</span>
<span class="cmt"># User 1's note is gone. Permanently.</span>

<span class="cmt"># Even worse: modify another user's note</span>
curl -X PUT \
  -b <span class="str">"session=USER2_SESSION"</span> \
  -H <span class="str">"Content-Type: application/json"</span> \
  -d <span class="str">'{"body": "This note has been tampered with"}'</span> \
  http://localhost:3000/api/notes/5
  </pre>
</div>

<p>
  Read-based IDOR gets you a confidentiality breach. Write-based IDOR gets you an integrity breach.
  Delete-based IDOR gets you an availability breach. Together, you have violated the entire CIA triad
  with one missing authorization check. And unlike read-based attacks, write and delete IDOR can be
  used for sabotage, defacement, or covering tracks after a broader compromise.
</p>

<div class="callout warn">
  <div class="callout-title">Every CRUD Operation Needs Authorization</div>
  <div class="callout-text">
    Do not only check ownership on GET endpoints. PUT, PATCH, and DELETE endpoints are equally
    vulnerable and often more damaging when exploited. The ownership check must be present on
    every single operation that touches user-specific resources.
  </div>
</div>

<hr>

<h2>Task Checklist</h2>

<ul class="task-list">
  <li><span class="task-check"></span> Build the notes API with sequential integer IDs and no ownership check on the GET endpoint</li>
  <li><span class="task-check"></span> Write and run the enumeration script to harvest all notes, including the admin API key</li>
  <li><span class="task-check"></span> Exploit write/delete IDOR: modify and delete another user's notes via PUT and DELETE requests</li>
  <li><span class="task-check"></span> Exploit the admin endpoint to demonstrate vertical privilege escalation without admin role</li>
  <li><span class="task-check"></span> Implement ownership checks using both the query-level and post-fetch patterns</li>
  <li><span class="task-check"></span> Verify that UUID-based endpoints are still vulnerable to IDOR when the UUID is known</li>
  <li><span class="task-check"></span> Add ownership checks to PUT, PATCH, and DELETE routes and verify all CRUD operations are protected</li>
</ul>

<div class="section-nav">
  <button class="nav-btn" data-prev="jwt">Previous: JWT Attacks</button>
  <button class="nav-btn" data-next="proto">Next: Prototype Pollution</button>
</div>

`;
