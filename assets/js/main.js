(function () {
  'use strict';

  /* ==================================================================
     NEURAL NETWORK — floating nodes with connections
     ================================================================== */
  var canvas = document.getElementById('starfield');
  if (canvas && window.matchMedia('(hover: hover)').matches) {
    var ctx = canvas.getContext('2d');
    var nodes = [];
    var NUM_NODES = 80;
    var LINK_DIST = 150;       // max distance to draw a connection
    var MOUSE_RADIUS = 200;    // mouse interaction radius
    var mx = -9999;
    var my = -9999;

    function resize() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      // Re-seed nodes when resizing
      if (nodes.length === 0) initNodes();
    }

    function initNodes() {
      nodes = [];
      for (var i = 0; i < NUM_NODES; i++) {
        nodes.push({
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          vx: (Math.random() - 0.5) * 0.4,
          vy: (Math.random() - 0.5) * 0.4,
          r: 1.5 + Math.random() * 1.5
        });
      }
    }

    resize();
    initNodes();
    window.addEventListener('resize', resize);

    document.addEventListener('mousemove', function (e) {
      mx = e.clientX;
      my = e.clientY;
    });

    document.addEventListener('mouseleave', function () {
      mx = -9999;
      my = -9999;
    });

    function tick() {
      requestAnimationFrame(tick);
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      var w = canvas.width;
      var h = canvas.height;

      // Update node positions
      for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i];
        n.x += n.vx;
        n.y += n.vy;

        // Wrap around edges
        if (n.x < 0) n.x = w;
        if (n.x > w) n.x = 0;
        if (n.y < 0) n.y = h;
        if (n.y > h) n.y = 0;
      }

      // Draw connections between nodes
      for (var i = 0; i < nodes.length; i++) {
        for (var j = i + 1; j < nodes.length; j++) {
          var dx = nodes[i].x - nodes[j].x;
          var dy = nodes[i].y - nodes[j].y;
          var dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < LINK_DIST) {
            var alpha = (1 - dist / LINK_DIST) * 0.15;
            ctx.strokeStyle = 'rgba(88, 166, 255, ' + alpha + ')';
            ctx.lineWidth = 0.5;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.stroke();
          }
        }
      }

      // Draw connections from mouse to nearby nodes + draw nodes
      for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i];

        // Mouse-to-node connection
        var dmx = n.x - mx;
        var dmy = n.y - my;
        var mouseDist = Math.sqrt(dmx * dmx + dmy * dmy);

        if (mouseDist < MOUSE_RADIUS) {
          var mAlpha = (1 - mouseDist / MOUSE_RADIUS) * 0.4;
          ctx.strokeStyle = 'rgba(88, 166, 255, ' + mAlpha + ')';
          ctx.lineWidth = 0.8;
          ctx.beginPath();
          ctx.moveTo(mx, my);
          ctx.lineTo(n.x, n.y);
          ctx.stroke();
        }

        // Node glow near mouse
        var glow = mouseDist < MOUSE_RADIUS ? (1 - mouseDist / MOUSE_RADIUS) : 0;
        var nodeAlpha = 0.3 + glow * 0.7;
        var nodeRadius = n.r + glow * 2;

        // Outer glow
        if (glow > 0) {
          var grd = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, nodeRadius * 3);
          grd.addColorStop(0, 'rgba(88, 166, 255, ' + (glow * 0.15) + ')');
          grd.addColorStop(1, 'rgba(88, 166, 255, 0)');
          ctx.fillStyle = grd;
          ctx.beginPath();
          ctx.arc(n.x, n.y, nodeRadius * 3, 0, Math.PI * 2);
          ctx.fill();
        }

        // Node dot
        ctx.fillStyle = 'rgba(88, 166, 255, ' + nodeAlpha + ')';
        ctx.beginPath();
        ctx.arc(n.x, n.y, nodeRadius, 0, Math.PI * 2);
        ctx.fill();
      }

      // Mouse node (bright center point)
      if (mx > 0 && my > 0) {
        ctx.fillStyle = 'rgba(88, 166, 255, 0.6)';
        ctx.beginPath();
        ctx.arc(mx, my, 3, 0, Math.PI * 2);
        ctx.fill();

        var mgrd = ctx.createRadialGradient(mx, my, 0, mx, my, 12);
        mgrd.addColorStop(0, 'rgba(88, 166, 255, 0.2)');
        mgrd.addColorStop(1, 'rgba(88, 166, 255, 0)');
        ctx.fillStyle = mgrd;
        ctx.beginPath();
        ctx.arc(mx, my, 12, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    requestAnimationFrame(tick);
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
