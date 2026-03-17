// ── JS AppSec Course — App Controller ──

(function () {
  'use strict';

  const SECTIONS = [
    'intro', 'setup', 'sqli', 'xss', 'cmdi', 'nosql',
    'csrf', 'jwt', 'idor', 'proto', 'deser', 'path',
    'regexdos', 'cors', 'csp', 'ratelimit', 'smuggling', 'capstone'
  ];

  const completed = new Set(JSON.parse(localStorage.getItem('appsec-completed') || '[]'));
  let currentSection = null;

  // ── Navigation ──

  function show(id) {
    if (!window.LESSONS || !window.LESSONS[id]) return;

    const content = document.getElementById('content');
    content.innerHTML = '<div class="lesson-wrap">' + window.LESSONS[id] + '</div>';
    content.scrollTop = 0;

    // Update sidebar active state
    document.querySelectorAll('.nav-item').forEach(function (el) {
      el.classList.toggle('active', el.dataset.section === id);
    });

    // Track progress
    completed.add(id);
    localStorage.setItem('appsec-completed', JSON.stringify([...completed]));
    updateProgress();

    currentSection = id;
  }

  function updateProgress() {
    const pct = Math.round((completed.size / SECTIONS.length) * 100);
    const fill = document.getElementById('prog-fill');
    const label = document.getElementById('prog-pct');
    if (fill) fill.style.width = pct + '%';
    if (label) label.textContent = pct + '%';
  }

  // ── Navigate to next/previous section ──

  function nextSection() {
    if (!currentSection) return;
    var idx = SECTIONS.indexOf(currentSection);
    if (idx < SECTIONS.length - 1) show(SECTIONS[idx + 1]);
  }

  function prevSection() {
    if (!currentSection) return;
    var idx = SECTIONS.indexOf(currentSection);
    if (idx > 0) show(SECTIONS[idx - 1]);
  }

  // ── Delegated event listeners ──

  document.addEventListener('click', function (e) {
    // Sidebar nav
    var navItem = e.target.closest('.nav-item');
    if (navItem && navItem.dataset.section) {
      show(navItem.dataset.section);
      return;
    }

    // Code copy
    var copyBtn = e.target.closest('.code-copy');
    if (copyBtn) {
      var block = copyBtn.closest('.code-block');
      var pre = block ? block.querySelector('pre') : null;
      if (pre) {
        navigator.clipboard.writeText(pre.innerText).then(function () {
          copyBtn.textContent = 'copied';
          copyBtn.style.color = '#27ae60';
          setTimeout(function () {
            copyBtn.textContent = 'copy';
            copyBtn.style.color = '';
          }, 1500);
        });
      }
      return;
    }

    // Task checkboxes
    var check = e.target.closest('.task-check');
    if (check) {
      check.classList.toggle('done');
      check.textContent = check.classList.contains('done') ? '\u2713' : '';
      return;
    }

    // Section nav buttons
    var navBtn = e.target.closest('.nav-btn');
    if (navBtn) {
      if (navBtn.dataset.next) show(navBtn.dataset.next);
      if (navBtn.dataset.prev) show(navBtn.dataset.prev);
      return;
    }
  });

  // ── Theme toggle ──

  function initTheme() {
    var saved = localStorage.getItem('appsec-theme');
    if (saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  }

  function toggleTheme() {
    var isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    if (isDark) {
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('appsec-theme', 'light');
    } else {
      document.documentElement.setAttribute('data-theme', 'dark');
      localStorage.setItem('appsec-theme', 'dark');
    }
  }

  initTheme();

  var themeSwitch = document.getElementById('theme-switch');
  if (themeSwitch) {
    themeSwitch.addEventListener('click', toggleTheme);
  }

  // ── Initialize ──

  window.show = show;
  window.nextSection = nextSection;
  window.prevSection = prevSection;

  updateProgress();
  show('intro');
})();
