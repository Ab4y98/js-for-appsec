window.LESSONS = window.LESSONS || {};
window.LESSONS.intro = `

<h1 class="lesson-title">JavaScript AppSec: Vulnerable by Design</h1>

<p class="lesson-subtitle">
  A hands-on security training course where you deliberately build, break, and fix vulnerable Node.js applications.
  Seventeen labs. Seventeen vulnerabilities. One very broken Express app.
</p>

<hr>

<h2>Why This Course Exists</h2>

<p>
  Let me be honest with you: most security training is terrible. You sit through slides about OWASP categories,
  nod along to abstract descriptions of injection attacks, maybe watch someone demo a tool you will never touch
  again, and then you go right back to writing the same vulnerable code you wrote before. I know because I sat
  through years of that training myself before I started actually breaking things.
</p>

<p>
  This course takes a fundamentally different approach. You are going to build a deliberately vulnerable web application
  from scratch using Express and Node.js. Then you are going to attack it. Not hypothetically. Not in a diagram.
  You will open a terminal, craft malicious inputs, watch your own code fail in spectacular ways, and then
  understand <em>exactly</em> why it failed and how to fix it. This is how security engineers actually learn their
  craft, and it is how you are going to learn it too.
</p>

<h2>What This Course Is</h2>

<p>
  This is a 17-lab, hands-on training program covering the OWASP Top 10 vulnerabilities as they appear in
  real-world Node.js and Express applications. Each lab follows a consistent structure: you will understand
  the vulnerability, build code that contains it, exploit that code yourself, and then implement the proper fix.
  No multiple-choice quizzes. No abstract threat models. Just you, your terminal, and code that is trying very
  hard to be broken.
</p>

<p>
  Everything here runs on localhost. There is no cloud infrastructure to provision, no Docker containers to
  wrangle (unless you want to), and no accounts to create. You need Node.js, a text editor, and a willingness
  to think like an attacker. That is it.
</p>

<h2>The Philosophy: Break It to Understand It</h2>

<p>
  There is a concept in security education called "red team thinking" -- you learn defense by first mastering
  offense. When you understand how an attacker sees your application, every line of code you write afterward
  carries that awareness. You stop writing <code>SELECT * FROM users WHERE id = '\${userId}'</code> not because
  a linter told you to, but because you can <em>feel</em> the injection point the moment your fingers type it.
</p>

<p>
  Each lab in this course follows a three-phase pattern:
</p>

<ol>
  <li><strong>Build the vulnerability.</strong> You will write intentionally insecure code. This is not a shortcut or a hack -- it is the code that actually ships in production applications every single day. You need to see it, write it, and understand why a reasonable developer might produce it.</li>
  <li><strong>Exploit it.</strong> You will craft payloads, manipulate requests, and watch your application do things it was never meant to do. This is where the real learning happens.</li>
  <li><strong>Fix it properly.</strong> Not with a band-aid. Not with a WAF rule. With correct code that addresses the root cause. You will understand why the fix works, not just that it works.</li>
</ol>

<h2>Who This Is For</h2>

<p>
  You are a developer. Maybe a junior developer who has heard the term "SQL injection" but never actually seen one.
  Maybe a senior engineer who has been writing Node.js for years and knows, somewhere in the back of your mind,
  that your input validation is not as thorough as it should be. Maybe you are moving into a security-focused role
  and need to build a practical foundation fast.
</p>

<p>
  Whatever your background, I assume you know JavaScript, have a basic understanding of how HTTP works, and have
  used Express or a similar framework at least once. I do not assume any prior security knowledge. If you can
  build a REST API, you are ready for this course.
</p>

<p>
  I will tell you who this is <em>not</em> for: people looking for a checkbox certification. There is no certificate
  at the end. What there is, is a working understanding of how real attacks happen and how real defenses work.
  That is worth more than any badge on a LinkedIn profile, and every interviewer who actually understands security
  will agree.
</p>

<h2>What You Will Build</h2>

<p>
  Over the course of these seventeen labs, you will build a deliberately vulnerable Express/Node.js web application.
  It is a simple multi-user platform with authentication, user profiles, posts, notes, and an admin panel. Nothing
  fancy on the surface. Under the hood, it is a minefield of security flaws -- every one of them modeled on
  vulnerabilities I have personally seen in production codebases at companies you have heard of.
</p>

<p>
  The tech stack is intentionally straightforward: Express for routing, EJS for server-side templating, SQLite and
  MongoDB for persistence, and standard npm packages for sessions, authentication, and serialization. No React,
  no Next.js, no GraphQL. We keep the stack simple so you can focus entirely on the security concepts without
  fighting framework abstractions.
</p>

<h2>The Seventeen Labs</h2>

<p>
  Here is what you will work through, lab by lab. Each one builds on the application you started in the
  previous lab, so by the end you will have a complete (and fully patched) application.
</p>

<ol>
  <li><strong>Lab 01 -- Environment Setup:</strong> You will scaffold the project, install dependencies, initialize databases, and get the deliberately insecure baseline application running on localhost.</li>
  <li><strong>Lab 02 -- SQL Injection:</strong> You will exploit authentication bypass, UNION-based data exfiltration, boolean-based blind injection, and time-based blind injection in login and search forms using SQLite, then fix them with parameterized queries and input validation.</li>
  <li><strong>Lab 03 -- Cross-Site Scripting (XSS):</strong> You will inject reflected, stored, and DOM-based XSS payloads through user input, steal session cookies, and then implement proper context-aware output encoding and Content Security Policy headers.</li>
  <li><strong>Lab 04 -- Command Injection:</strong> You will build an endpoint that runs system commands, inject your own commands using semicolons, AND chains, subshell substitution, and backticks, escalate to a reverse shell, and then learn why execFile exists and why exec should terrify you.</li>
  <li><strong>Lab 05 -- NoSQL Injection:</strong> You will attack MongoDB queries using operator injection ($ne, $gt, $regex, $where), extract passwords character by character, and then learn how schema validation and query sanitization stop these attacks cold.</li>
  <li><strong>Lab 06 -- Cross-Site Request Forgery (CSRF):</strong> You will craft malicious pages with auto-submitting forms, image-tag GET attacks, and login CSRF, then deploy anti-CSRF tokens and SameSite cookies to stop them.</li>
  <li><strong>Lab 07 -- JWT Attacks:</strong> You will exploit the alg:none vulnerability, brute-force weak signing secrets, and abuse algorithm confusion to forge tokens, then lock down JWT verification with proper configuration.</li>
  <li><strong>Lab 08 -- Insecure Direct Object References (IDOR):</strong> You will access other users' private data by enumerating sequential IDs, automate bulk extraction, exploit write/delete IDOR to destroy resources, and then implement proper authorization checks that verify ownership.</li>
  <li><strong>Lab 09 -- Prototype Pollution:</strong> You will poison the prototype chain through deep merge functions, constructor.prototype bypasses, and query-string injection, then chain it into privilege escalation and RCE.</li>
  <li><strong>Lab 10 -- Insecure Deserialization:</strong> You will achieve remote code execution through node-serialize IIFE injection, escalate to a reverse shell, exploit YAML deserialization, and then learn why you should never deserialize untrusted input.</li>
  <li><strong>Lab 11 -- Path Traversal:</strong> You will escape intended directories using dot-dot-slash sequences, bypass filters with double encoding and null bytes, exploit route parameter traversal, and learn about Zip Slip attacks.</li>
  <li><strong>Lab 12 -- ReDoS:</strong> You will craft inputs that cause catastrophic backtracking in email validation, URL parsing, and User-Agent matching regexes, block the Node.js event loop, and then fix patterns using atomic groups and the RE2 engine.</li>
  <li><strong>Lab 13 -- CORS Misconfiguration:</strong> You will exploit origin reflection, null origin abuse, and subdomain wildcard bypasses to steal authenticated data cross-origin, then configure CORS properly with explicit allowlists.</li>
  <li><strong>Lab 14 -- Content Security Policy (CSP):</strong> You will bypass weak CSP configurations using unsafe-inline, JSONP endpoints, and base-uri hijacking, then implement strict nonce-based CSP that actually stops XSS.</li>
  <li><strong>Lab 15 -- Rate-Limiting &amp; Brute Force:</strong> You will brute-force unprotected login endpoints, bypass IP-based rate limits using X-Forwarded-For manipulation, and exploit response timing side-channels, then build layered defenses with express-rate-limit.</li>
  <li><strong>Lab 16 -- HTML Smuggling:</strong> You will construct malicious files client-side using Blob URLs and data URIs to bypass proxy and email scanning, exploit anchor tag download tricks, and use encoding obfuscation to evade static analysis.</li>
  <li><strong>Lab 17 -- Server-Side Request Forgery (SSRF):</strong> You will trick the server into fetching internal resources by abusing URL preview endpoints, steal cloud metadata credentials from 169.254.169.254, read local files via file:// protocol abuse, and detect blind SSRF using out-of-band callbacks, then build layered defenses with DNS resolution validation and private IP blocking.</li>
</ol>

<h2>How Long Will This Take?</h2>

<p>
  Plan for roughly eight hours total, spread however you like. Some labs are shorter (Environment Setup is
  about 20 minutes if everything installs cleanly), and some are longer (SQL Injection and XSS each deserve
  a solid hour of exploration). I strongly recommend doing no more than two or three labs in a single sitting.
  Security concepts need time to settle in your mind. You will get more out of this course if you sleep on each
  lab before moving to the next one.
</p>

<p>
  That said, if you are the type who locks in for an entire Saturday with a pot of coffee and a terminal, I respect
  that too. Do what works for you.
</p>

<div class="callout warn">
  <div class="callout-title">A Note About Ethics</div>
  <div class="callout-text">
    Everything in this course runs on <strong>localhost only</strong>. You will be learning real attack techniques
    that work on real systems. That knowledge comes with responsibility. Never test these techniques on systems
    you do not own or do not have explicit written permission to test. Unauthorized access to computer systems
    is a criminal offense in virtually every jurisdiction on the planet, and "I was just learning" is not a legal
    defense. Keep it on your own machine, and you will be fine.
  </div>
</div>

<div class="callout info">
  <div class="callout-title">What You Will Walk Away With</div>
  <div class="callout-text">
    By the end of these seventeen labs, you will have an intuitive understanding of how the most common web
    vulnerabilities work at a code level. You will be able to spot injection points in code review, design
    authentication systems that do not fall apart under pressure, and have a working mental model of how attackers
    think. That mental model is the single most valuable thing a developer can carry into any security conversation.
  </div>
</div>

<hr>

<p>
  Ready to get started? The next lab walks you through setting up your development environment, scaffolding
  the project, and getting the baseline vulnerable application running. It is the only lab where you will
  not break anything -- but do not worry. That starts soon enough.
</p>

<div class="section-nav">
  <span></span>
  <button class="nav-btn" data-next="setup">Next: Environment Setup</button>
</div>

`;
