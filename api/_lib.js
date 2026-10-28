// Shared SIEM engine. Storage = Upstash Redis (REST API, no npm packages needed).
const U = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const T = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

async function rd(...cmds) {
  if (!U || !T) throw new Error("Redis is not connected. In Vercel: Storage > Upstash Redis > connect to this project, then redeploy.");
  const r = await fetch(U + "/pipeline", {
    method: "POST",
    headers: { Authorization: "Bearer " + T },
    body: JSON.stringify(cmds.map(c => c.map(String)))
  });
  if (!r.ok) throw new Error("Redis error " + r.status);
  return (await r.json()).map(x => x.result);
}

const RULES = {
  BF: ["Brute force login", "High"], PS: ["Port scan", "Medium"], SQLI: ["SQL injection", "High"],
  XSS: ["Cross-site scripting", "Medium"], MAL: ["Malware beacon", "Critical"], PE: ["Privilege escalation", "Critical"]
};
const MAP = { auth_fail: "BF", port: "PS", sqli: "SQLI", xss: "XSS", malware: "MAL", sudo: "PE" };

// Decide what kind of event a raw log line is
function classify(e) {
  let m = e.msg;
  try { m = decodeURIComponent(m); } catch (_) {}
  const u = /for (?:invalid user )?(\S+) from/i.exec(m);
  if (u && !e.user) e.user = u[1];
  if (e.type) return;
  const p = /DPT=(\d+)|:(\d+)\s*$/i.exec(m);
  if (/<script|onerror=|javascript:/i.test(m)) e.type = "xss";
  else if (/union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|'--|;\s*drop\s|sleep\(/i.test(m)) e.type = "sqli";
  else if (/beacon|\bc2\b|ransom|trojan|mimikatz|malware/i.test(m)) e.type = "malware";
  else if (/gained root|Accepted \S+ for root|su: .*to root/i.test(m)) e.type = "sudo";
  else if (/failed password|authentication failure|invalid user/i.test(m)) e.type = "auth_fail";
  else if (/deny|drop|reject/i.test(m) && p) { e.type = "port"; e.port = p[1] || p[2]; }
  else e.type = "info";
}

async function raise(k, e, detail) {
  const dk = "siem:dd:" + k + ":" + e.ip;
  const [id] = await rd(["GET", dk]);
  if (id) { // same alert still open: just bump the counter
    const [a] = await rd(["HGET", "siem:alerts", id]);
    if (a) {
      const o = JSON.parse(a);
      if (o.status !== "Resolved") { o.count++; await rd(["HSET", "siem:alerts", id, JSON.stringify(o)]); return; }
    }
  }
  const [nid] = await rd(["INCR", "siem:aid"]);
  const bk = Math.floor(Date.now() / 5000);
  const o = { id: nid, time: Date.now(), type: k, name: RULES[k][0], sev: RULES[k][1], ip: e.ip, detail: String(detail).slice(0, 200), status: "New", count: 1 };
  await rd(["HSET", "siem:alerts", nid, JSON.stringify(o)], ["SET", dk, nid, "EX", 30],
    ["HINCRBY", "siem:rc", k, 1], ["INCR", "siem:ba:" + bk], ["EXPIRE", "siem:ba:" + bk, 300]);
}

// Store one log event and run detection rules on it
async function ingest(raw) {
  const t = Date.now();
  const e = {
    t, src: String(raw.source || raw.src || "APP").toUpperCase().slice(0, 12),
    lvl: ["info", "warn", "error", "crit"].includes(raw.level) ? raw.level : "info",
    msg: String(raw.message || raw.msg || "").slice(0, 400), ip: String(raw.ip || ""),
    type: raw.type, user: raw.user, port: raw.port
  };
  if (!e.ip) { const m = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/.exec(e.msg); e.ip = m ? m[1] : "unknown"; }
  classify(e);
  const bk = Math.floor(t / 5000);
  const [blocked] = await rd(["SISMEMBER", "siem:blocked", e.ip]);
  await rd(["LPUSH", "siem:logs", JSON.stringify({ t, src: e.src, lvl: e.lvl, ip: e.ip, msg: e.msg })],
    ["LTRIM", "siem:logs", 0, 299], ["INCR", "siem:total"], ["INCR", "siem:be:" + bk], ["EXPIRE", "siem:be:" + bk, 300]);
  if (blocked) { await rd(["INCR", "siem:dropped"]); return; } // blocked IP: log it, no new alerts
  const k = MAP[e.type];
  if (!k) return;
  if (k === "BF") {
    const [n] = await rd(["INCR", "siem:fail:" + e.ip], ["EXPIRE", "siem:fail:" + e.ip, 60]);
    if (n >= 5) { await raise(k, e, n + " failed logins in 60s, last user: " + (e.user || "?")); await rd(["DEL", "siem:fail:" + e.ip]); }
  } else if (k === "PS") {
    const [, n] = await rd(["SADD", "siem:ports:" + e.ip, e.port], ["SCARD", "siem:ports:" + e.ip], ["EXPIRE", "siem:ports:" + e.ip, 30]);
    if (n >= 8) { await raise(k, e, n + " distinct ports probed in 30s"); await rd(["DEL", "siem:ports:" + e.ip]); }
  } else await raise(k, e, e.msg);
}

// Everything the dashboard needs in one call
async function stats() {
  const bk = Math.floor(Date.now() / 5000), ks = [...Array(24)].map((_, i) => bk - 23 + i);
  const [logs, al, tot, dr, bl, rc, be, ba] = await rd(
    ["LRANGE", "siem:logs", 0, 99], ["HGETALL", "siem:alerts"], ["GET", "siem:total"], ["GET", "siem:dropped"],
    ["SMEMBERS", "siem:blocked"], ["HGETALL", "siem:rc"],
    ["MGET", ...ks.map(k => "siem:be:" + k)], ["MGET", ...ks.map(k => "siem:ba:" + k)]);
  const alerts = [];
  for (let i = 1; i < al.length; i += 2) alerts.push(JSON.parse(al[i]));
  alerts.sort((a, b) => b.time - a.time);
  const R = { BF: 0, PS: 0, SQLI: 0, XSS: 0, MAL: 0, PE: 0 };
  for (let i = 0; i < rc.length; i += 2) R[rc[i]] = +rc[i + 1];
  return {
    logs: logs.map(x => JSON.parse(x)), alerts: alerts.slice(0, 100), total: +tot || 0, dropped: +dr || 0,
    blocked: bl, rc: R, b: ks.map((_, i) => ({ e: +be[i] || 0, a: +ba[i] || 0 }))
  };
}

module.exports = { rd, ingest, stats };
