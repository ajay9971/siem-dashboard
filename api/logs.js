const { rd, ingest, stats } = require("./_lib");

// GET  /api/logs  -> logs, alerts, counters for the dashboard
// POST /api/logs  -> { action: inv | res | blk | demo | reset }
module.exports = async (req, res) => {
  try {
    const pw = process.env.DASH_PASSWORD;
    if (!pw) return res.status(500).send("Set DASH_PASSWORD in Vercel Environment Variables, then redeploy.");
    if (req.headers["x-dash-key"] !== pw) return res.status(401).send("Unauthorized");

    if (req.method === "POST") {
      const b = req.body || {};
      if (b.action === "inv" || b.action === "res") {
        const [a] = await rd(["HGET", "siem:alerts", b.id]);
        if (a) {
          const o = JSON.parse(a);
          o.status = b.action === "inv" ? "Investigating" : "Resolved";
          await rd(["HSET", "siem:alerts", b.id, JSON.stringify(o)]);
        }
      } else if (b.action === "blk" && b.ip) {
        const [al] = await rd(["HGETALL", "siem:alerts"]);
        for (let i = 1; i < al.length; i += 2) {
          const o = JSON.parse(al[i]);
          if (o.ip === b.ip && o.status !== "Resolved") {
            o.status = "Resolved";
            await rd(["HSET", "siem:alerts", o.id, JSON.stringify(o)]);
          }
        }
        await rd(["SADD", "siem:blocked", b.ip],
          ["LPUSH", "siem:logs", JSON.stringify({ t: Date.now(), src: "SOAR", lvl: "info", ip: b.ip, msg: "Analyst blocked " + b.ip })]);
      } else if (b.action === "demo") {
        // Sends test events through the real pipeline (same path as the agent)
        const ip = "185.220.101." + (1 + Math.floor(Math.random() * 250));
        for (let i = 0; i < 5; i++)
          await ingest({ source: "AUTH", level: "warn", ip, message: "Failed password for root from " + ip + " port 22 ssh2" });
        for (const p of [21, 22, 23, 25, 80, 445, 3306, 3389])
          await ingest({ source: "FIREWALL", level: "warn", ip, message: "DROP IN=eth0 SRC=" + ip + " DPT=" + p });
        await ingest({ source: "WEB", level: "error", ip, message: "GET /login?user=admin'-- 500" });
      } else if (b.action === "reset") {
        await rd(["DEL", "siem:logs"], ["DEL", "siem:alerts"], ["DEL", "siem:total"], ["DEL", "siem:dropped"],
          ["DEL", "siem:blocked"], ["DEL", "siem:rc"], ["DEL", "siem:aid"]);
      }
    }
    res.setHeader("Cache-Control", "no-store");
    res.json(await stats());
  } catch (err) {
    res.status(500).send(String(err.message || err));
  }
};
