(function () {
  'use strict';

  /* ---- Mouse glow effect ---- */
  var glowActive = false;
  var rafId = null;
  var mx = 0;
  var my = 0;

  document.addEventListener('mousemove', function (e) {
    mx = e.clientX;
    my = e.clientY;

    if (!glowActive) {
      glowActive = true;
      document.body.classList.add('glow-active');
    }

    if (!rafId) {
      rafId = requestAnimationFrame(function () {
        document.body.style.setProperty('--glow-x', mx + 'px');
        document.body.style.setProperty('--glow-y', my + 'px');
        rafId = null;
      });
    }
  });

  document.addEventListener('mouseleave', function () {
    glowActive = false;
    document.body.classList.remove('glow-active');
  });

  /* ---- Sidebar toggle ---- */
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

  function toggleSidebar() {
    if (sidebar.classList.contains('is-open')) {
      closeSidebar();
    } else {
      openSidebar();
    }
  }

  hamburger.addEventListener('click', toggleSidebar);
  if (overlay) overlay.addEventListener('click', closeSidebar);

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeSidebar();
  });

  window.matchMedia('(min-width: 1024px)').addEventListener('change', function (e) {
    if (e.matches) closeSidebar();
  });
})();
