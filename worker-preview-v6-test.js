export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/api/check") {
      return jsonResponse(buildResult(request));
    }

    if (url.pathname === "/api/ip") {
      const result = buildResult(request);
      return new Response(result.ip + "\n", {
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
        },
      });
    }

    return new Response(renderPage(), {
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  },
};

function buildResult(request) {
  const ip = request.headers.get("cf-connecting-ip") || "";
  const ray = request.headers.get("cf-ray") || "";
  const colo = ray.includes("-") ? ray.split("-").pop() : "";
  const cf = request.cf || {};
  const version = detectIpVersion(ip);

  return {
    ok: version === 6,
    ip,
    version,
    is_ipv6: version === 6,
    is_ipv4: version === 4,
    colo,
    country: cf.country || "",
    city: cf.city || "",
    asn: cf.asn || null,
    as_organization: cf.asOrganization || "",
    user_agent: request.headers.get("user-agent") || "",
    time: new Date().toISOString(),
  };
}

function detectIpVersion(ip) {
  if (!ip) return 0;
  if (ip.includes(":")) return 6;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)) return 4;
  return 0;
}

function jsonResponse(data) {
  return new Response(JSON.stringify(data, null, 2), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
    },
  });
}

function renderPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Worker Preview IPv6 检测</title>
  <style>
    :root { color-scheme: light dark; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #0f172a; color: #e5e7eb; }
    main { width: min(760px, calc(100% - 32px)); padding: 28px; border: 1px solid rgba(148,163,184,.28); border-radius: 22px; background: rgba(15,23,42,.86); box-shadow: 0 24px 70px rgba(0,0,0,.28); }
    h1 { margin: 0 0 10px; font-size: clamp(28px, 5vw, 44px); }
    p { color: #94a3b8; line-height: 1.7; }
    .status { margin: 22px 0; padding: 18px; border-radius: 16px; background: #111827; border: 1px solid rgba(148,163,184,.22); }
    .badge { display: inline-flex; padding: 6px 12px; border-radius: 999px; font-weight: 800; }
    .ok { color: #bbf7d0; background: rgba(22,163,74,.18); }
    .bad { color: #fecaca; background: rgba(220,38,38,.18); }
    dl { display: grid; grid-template-columns: 140px 1fr; gap: 10px; }
    dt { color: #94a3b8; }
    dd { margin: 0; overflow-wrap: anywhere; }
    button, a { display: inline-flex; align-items: center; gap: 8px; border: 0; border-radius: 999px; padding: 10px 14px; font: inherit; font-weight: 700; color: #0f172a; background: #38bdf8; cursor: pointer; text-decoration: none; }
    pre { overflow: auto; padding: 14px; border-radius: 14px; background: #020617; color: #dbeafe; }
    @media (max-width: 560px) { main { padding: 20px; } dl { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <main>
    <h1>Worker Preview IPv6 检测</h1>
    <p>此页面通过 Worker 读取 <code>CF-Connecting-IP</code> 判断当前访问是否走 IPv6。若结果为 IPv4，说明浏览器本次连接 Worker 时没有使用 IPv6。</p>
    <div class="status">
      <span id="badge" class="badge">检测中...</span>
      <dl>
        <dt>公网 IP</dt><dd id="ip">-</dd>
        <dt>IP 版本</dt><dd id="version">-</dd>
        <dt>Cloudflare 节点</dt><dd id="colo">-</dd>
        <dt>位置</dt><dd id="location">-</dd>
        <dt>ASN</dt><dd id="asn">-</dd>
        <dt>检测时间</dt><dd id="time">-</dd>
      </dl>
    </div>
    <button id="rerun" type="button">重新检测</button>
    <a href="/api/check" target="_blank" rel="noreferrer">查看 JSON</a>
    <pre id="raw">等待检测...</pre>
  </main>
  <script>
    const $ = id => document.getElementById(id);

    async function run() {
      const started = performance.now();
      const res = await fetch('/api/check?ts=' + Date.now(), { cache: 'no-store' });
      const data = await res.json();
      data.latency_ms = Math.max(1, Math.round(performance.now() - started));

      $('badge').textContent = data.is_ipv6 ? 'IPv6 可用' : '未使用 IPv6';
      $('badge').className = 'badge ' + (data.is_ipv6 ? 'ok' : 'bad');
      $('ip').textContent = data.ip || '-';
      $('version').textContent = data.version ? 'IPv' + data.version : '未知';
      $('colo').textContent = data.colo || '-';
      $('location').textContent = [data.country, data.city].filter(Boolean).join(' / ') || '-';
      $('asn').textContent = data.asn ? data.asn + ' ' + (data.as_organization || '') : '-';
      $('time').textContent = data.time + '，延迟 ' + data.latency_ms + ' ms';
      $('raw').textContent = JSON.stringify(data, null, 2);
    }

    $('rerun').addEventListener('click', run);
    run().catch(err => {
      $('badge').textContent = '检测失败';
      $('badge').className = 'badge bad';
      $('raw').textContent = String(err && err.stack || err);
    });
  </script>
</body>
</html>`;
}
