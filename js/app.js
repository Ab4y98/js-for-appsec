// ── JS AppSec Course — App Controller ──

(function () {
  'use strict';

  const SECTIONS = [
    'intro', 'setup', 'sqli', 'xss', 'cmdi', 'nosql',
    'csrf', 'jwt', 'idor', 'proto', 'deser', 'path',
    'regexdos', 'cors', 'csp', 'ratelimit', 'smuggling', 'ssrf', 'capstone'
  ];

  // ── Checklist persistence ──
  // Store: { sectionId: [0, 2, 5], ... } — indices of checked items per section
  var checklistState = JSON.parse(localStorage.getItem('appsec-checks') || '{}');
  var totalChecklistItems = 0;
  var currentSection = null;

  // Count total checklist items across all lessons (done once at init)
  function countAllChecklistItems() {
    var total = 0;
    SECTIONS.forEach(function (id) {
      if (!window.LESSONS || !window.LESSONS[id]) return;
      // Count occurrences of task-check spans in the HTML string
      var matches = window.LESSONS[id].match(/task-check/g);
      if (matches) total += matches.length;
    });
    return total;
  }

  // Count total checked items across all sections
  function countCheckedItems() {
    var count = 0;
    Object.keys(checklistState).forEach(function (key) {
      if (Array.isArray(checklistState[key])) {
        count += checklistState[key].length;
      }
    });
    return count;
  }

  function saveChecklistState() {
    localStorage.setItem('appsec-checks', JSON.stringify(checklistState));
  }

  // Restore checked state for the current section after DOM injection
  function restoreChecklist(sectionId) {
    var checked = checklistState[sectionId] || [];
    var items = document.querySelectorAll('.task-check');
    items.forEach(function (el, idx) {
      if (checked.indexOf(idx) !== -1) {
        el.classList.add('done');
        el.textContent = '\u2713';
      }
    });
  }

  // ── Progress ──

  function updateProgress() {
    if (totalChecklistItems === 0) return;
    var checked = countCheckedItems();
    var pct = Math.round((checked / totalChecklistItems) * 100);
    var fill = document.getElementById('prog-fill');
    var label = document.getElementById('prog-pct');
    if (fill) fill.style.width = pct + '%';
    if (label) label.textContent = pct + '%';

    // Update sidebar checkmarks — mark section as complete when all its items are done
    SECTIONS.forEach(function (id) {
      if (!window.LESSONS || !window.LESSONS[id]) return;
      var matches = window.LESSONS[id].match(/task-check/g);
      var sectionTotal = matches ? matches.length : 0;
      var sectionChecked = (checklistState[id] || []).length;
      var navItem = document.querySelector('.nav-item[data-section="' + id + '"]');
      if (navItem) {
        if (sectionTotal > 0 && sectionChecked === sectionTotal) {
          navItem.classList.add('section-done');
        } else {
          navItem.classList.remove('section-done');
        }
      }
    });
  }

  // ── Navigation ──

  function show(id) {
    if (!window.LESSONS || !window.LESSONS[id]) return;

    var content = document.getElementById('content');
    content.innerHTML = '<div class="lesson-wrap">' + window.LESSONS[id] + '</div>';
    content.scrollTop = 0;

    // Update sidebar active state
    document.querySelectorAll('.nav-item').forEach(function (el) {
      el.classList.toggle('active', el.dataset.section === id);
    });

    currentSection = id;

    // Restore checklist state for this section
    restoreChecklist(id);
    updateProgress();
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

    // Task checkboxes — toggle, persist, and update progress
    var check = e.target.closest('.task-check');
    if (check) {
      check.classList.toggle('done');
      check.textContent = check.classList.contains('done') ? '\u2713' : '';

      // Find the index of this checkbox within the current section
      var allChecks = document.querySelectorAll('.task-check');
      var idx = -1;
      allChecks.forEach(function (el, i) {
        if (el === check) idx = i;
      });

      if (currentSection && idx !== -1) {
        if (!checklistState[currentSection]) {
          checklistState[currentSection] = [];
        }
        var arr = checklistState[currentSection];
        var pos = arr.indexOf(idx);
        if (check.classList.contains('done')) {
          if (pos === -1) arr.push(idx);
        } else {
          if (pos !== -1) arr.splice(pos, 1);
        }
        saveChecklistState();
        updateProgress();
      }
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

  totalChecklistItems = countAllChecklistItems();
  updateProgress();
  show('intro');
})();
