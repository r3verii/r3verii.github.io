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

/* ==================================================================
   IMAGE LIGHTBOX — click a post image to open it full-screen,
   click the image to zoom (pan with the mouse), click outside or Esc to close.
   Separate IIFE so the early return in the block above cannot skip it.
   ================================================================== */
(function () {
  'use strict';

  var imgs = document.querySelectorAll('.post-content img');
  if (!imgs.length) return;

  var overlay = document.createElement('div');
  overlay.className = 'lightbox-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-label', 'Image viewer');

  var big = document.createElement('img');
  big.alt = '';

  var closeBtn = document.createElement('button');
  closeBtn.className = 'lightbox-close';
  closeBtn.setAttribute('aria-label', 'Close');
  closeBtn.innerHTML = '&times;';

  overlay.appendChild(big);
  overlay.appendChild(closeBtn);
  document.body.appendChild(overlay);

  function resetZoom() {
    big.classList.remove('zoomed');
    big.style.transform = '';
    big.style.transformOrigin = 'center center';
  }
  function open(src, alt) {
    big.src = src;
    big.alt = alt || '';
    resetZoom();
    overlay.classList.add('is-open');
    document.body.classList.add('lightbox-open');
  }
  function close() {
    overlay.classList.remove('is-open');
    document.body.classList.remove('lightbox-open');
    resetZoom();
  }

  for (var i = 0; i < imgs.length; i++) {
    (function (im) {
      if (im.closest('a')) return; // leave linked images as links
      im.addEventListener('click', function () {
        open(im.currentSrc || im.src, im.alt);
      });
    })(imgs[i]);
  }

  big.addEventListener('click', function (e) {
    e.stopPropagation();
    if (big.classList.contains('zoomed')) {
      resetZoom();
    } else {
      var z = (big.naturalWidth && big.clientWidth)
        ? Math.min(Math.max(big.naturalWidth / big.clientWidth, 1.6), 4)
        : 2;
      big.classList.add('zoomed');
      big.style.transform = 'scale(' + z + ')';
    }
  });

  overlay.addEventListener('mousemove', function (e) {
    if (!big.classList.contains('zoomed')) return;
    var x = (e.clientX / window.innerWidth) * 100;
    var y = (e.clientY / window.innerHeight) * 100;
    big.style.transformOrigin = x + '% ' + y + '%';
  });

  overlay.addEventListener('click', close);
  closeBtn.addEventListener('click', function (e) { e.stopPropagation(); close(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && overlay.classList.contains('is-open')) close();
  });
})();

/* ==================================================================
   READING PROGRESS BAR — a thin line at the top that fills up as you
   scroll through a post. Separate IIFE; only runs on pages with a post.
   ================================================================== */
(function () {
  'use strict';
  if (!document.querySelector('.post-content')) return;

  var bar = document.createElement('div');
  bar.className = 'reading-progress';
  document.body.appendChild(bar);

  var ticking = false;
  function set() {
    var st = window.scrollY || document.documentElement.scrollTop;
    var h = document.documentElement.scrollHeight - window.innerHeight;
    bar.style.width = (h > 0 ? Math.min(st / h, 1) * 100 : 0) + '%';
    ticking = false;
  }
  function onScroll() {
    if (!ticking) { ticking = true; requestAnimationFrame(set); }
  }
  set();
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll);
})();

/* ==================================================================
   SCROLL CAT — a little cat sitting just below the tip of the reading-
   progress bar. Still frontal image when idle; spins (pure rotation)
   as soon as the page moves. Spin webp is preloaded so it is instant.
   Separate IIFE; only on pages with a post.
   ================================================================== */
(function () {
  'use strict';
  if (!document.querySelector('.post-content')) return;

  var STILL = '/assets/img/scroll-cat-static.png';
  var SPIN  = '/assets/img/scroll-cat-spin.webp';
  var W = 30;

  var pre = new Image(); pre.src = SPIN;   // preload so the spin is instant

  var cat = document.createElement('img');
  cat.className = 'scroll-cat';
  cat.src = STILL;
  cat.alt = '';
  cat.setAttribute('aria-hidden', 'true');
  document.body.appendChild(cat);

  var spinning = false, stopTimer = null, ticking = false;

  function vw() { return document.documentElement.clientWidth || window.innerWidth; }
  function place() {
    var st = window.scrollY || document.documentElement.scrollTop;
    var h = document.documentElement.scrollHeight - window.innerHeight;
    var p = h > 0 ? Math.min(Math.max(st / h, 0), 1) : 0;
    var x = p * vw() - W / 2;
    x = Math.max(0, Math.min(x, vw() - W));
    cat.style.left = x + 'px';
    ticking = false;
  }
  function onScroll() {
    if (!spinning) { cat.src = SPIN; spinning = true; }
    clearTimeout(stopTimer);
    stopTimer = setTimeout(function () { cat.src = STILL; spinning = false; }, 200);
    if (!ticking) { ticking = true; requestAnimationFrame(place); }
  }
  place();
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', function () {
    if (!ticking) { ticking = true; requestAnimationFrame(place); }
  });
})();
