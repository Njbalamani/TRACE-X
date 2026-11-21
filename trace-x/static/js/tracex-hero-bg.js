/* TRACE-X animated hero background: hex-column rain + particle constellation */
(function () {
  var c = document.getElementById('tx-bg-fx');
  if (!c || !c.getContext) return;
  var x = c.getContext('2d'), W, H, cols = [], pts = [], dpr = Math.min(window.devicePixelRatio || 1, 2);
  var rm = window.matchMedia && matchMedia('(prefers-reduced-motion:reduce)').matches, mx = 0, my = 0;
  function rs() {
    W = innerWidth; H = innerHeight;
    c.width = W * dpr; c.height = H * dpr;
    x.setTransform(dpr, 0, 0, dpr, 0, 0);
    cols = [];
    for (var i = 0; i < Math.floor(W / 46); i++) {
      cols.push({ x: i * 46 + 10, y: Math.random() * H, s: .25 + Math.random() * .5, t: Math.random() * 8 });
    }
    pts = [];
    for (i = 0; i < Math.min(60, W / 22); i++) {
      pts.push({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - .5) * .15, vy: (Math.random() - .5) * .15, r: Math.random() * 1.4 + .4 });
    }
  }
  rs();
  addEventListener('resize', rs);
  addEventListener('mousemove', function (e) {
    mx = (e.clientX / W - .5); my = (e.clientY / H - .5);
  });
  var hx = '0123456789ABCDEF';
  function draw() {
    x.clearRect(0, 0, W, H);
    x.font = '11px "JetBrains Mono", monospace';
    var i, j, k;
    for (i = 0; i < cols.length; i++) {
      k = cols[i];
      for (j = 0; j < 9; j++) {
        x.fillStyle = 'rgba(232,194,90,' + (0.07 * (1 - j / 9)) + ')';
        x.fillText(hx[(k.t * 3 + j + i) % 16 | 0] + hx[(i * 7 + j * 3) % 16], k.x + mx * 8, k.y - j * 14);
      }
      if (!rm) {
        k.y += k.s; k.t += .02;
        if (k.y > H + 140) { k.y = -20; }
      }
    }
    for (i = 0; i < pts.length; i++) {
      var p = pts[i];
      if (!rm) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > W) p.vx *= -1;
        if (p.y < 0 || p.y > H) p.vy *= -1;
      }
      x.fillStyle = i % 7 === 0 ? 'rgba(181,140,255,.55)' : 'rgba(232,194,90,.5)';
      x.beginPath(); x.arc(p.x + mx * 14, p.y + my * 14, p.r, 0, 6.283); x.fill();
      for (var q = i + 1; q < pts.length; q++) {
        var d = Math.hypot(p.x - pts[q].x, p.y - pts[q].y);
        if (d < 110) {
          x.strokeStyle = 'rgba(232,194,90,' + (0.09 * (1 - d / 110)) + ')';
          x.beginPath();
          x.moveTo(p.x + mx * 14, p.y + my * 14);
          x.lineTo(pts[q].x + mx * 14, pts[q].y + my * 14);
          x.stroke();
        }
      }
    }
    if (!rm) requestAnimationFrame(draw);
  }
  draw();
})();
