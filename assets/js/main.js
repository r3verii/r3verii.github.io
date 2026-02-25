(function () {
  'use strict';

  /* ==================================================================
     GNOME TOP PANEL CLOCK
     ================================================================== */
  var clockEl = document.getElementById('gnome-clock');
  if (clockEl) {
    var days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    function tick() {
      var now = new Date();
      var h = now.getHours(), m = now.getMinutes();
      clockEl.textContent = days[now.getDay()] + ' ' + now.getDate() + ' ' +
        months[now.getMonth()] + '  ' + (h < 10 ? '0' : '') + h + ':' + (m < 10 ? '0' : '') + m;
    }
    tick();
    setInterval(tick, 30000);
  }

  /* ==================================================================
     BURP HTTP STYLE — add class to HTTP code blocks
     ================================================================== */
  var allPre = document.querySelectorAll('pre');
  for (var i = 0; i < allPre.length; i++) {
    var code = allPre[i].querySelector('code');
    if (code && (code.className || '').indexOf('language-http') > -1) {
      allPre[i].classList.add('burp-repeater');
    }
  }

  /* ==================================================================
     SIDEBAR TOGGLE
     ================================================================== */
  var hamburger = document.querySelector('.hamburger');
  var sidebar = document.querySelector('.sidebar');
  var overlay = document.querySelector('.sidebar-overlay');
  if (!hamburger || !sidebar) return;

  function openSidebar() {
    sidebar.classList.add('is-open');
    document.body.classList.add('sidebar-open');
    if (overlay) overlay.classList.add('is-visible');
    hamburger.setAttribute('aria-expanded', 'true');
    document.body.style.overflow = 'hidden';
  }
  function closeSidebar() {
    sidebar.classList.remove('is-open');
    document.body.classList.remove('sidebar-open');
    if (overlay) overlay.classList.remove('is-visible');
    hamburger.setAttribute('aria-expanded', 'false');
    document.body.style.overflow = '';
  }
  hamburger.addEventListener('click', function () {
    sidebar.classList.contains('is-open') ? closeSidebar() : openSidebar();
  });
  if (overlay) overlay.addEventListener('click', closeSidebar);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeSidebar(); });
  window.matchMedia('(min-width: 1024px)').addEventListener('change', function (e) {
    if (e.matches) closeSidebar();
  });

})();
