const { ingest } = require("./_lib");

// POST /api/ingest   header: x-api-key   body: one event or an array of events
// event = { source, level, message, ip? }
module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).send("Use POST");
  const key = process.env.INGEST_KEY;
  if (!key) return res.status(500).send("Set INGEST_KEY in Vercel Environment Variables, then redeploy.");
  if (req.headers["x-api-key"] !== key) return res.status(401).send("Unauthorized");
  const events = Array.isArray(req.body) ? req.body : [req.body];
  try {
    for (const e of events.slice(0, 50)) await ingest(e || {});
    res.json({ ok: events.length });
  } catch (err) {
    res.status(500).send(String(err.message || err));
  }
};
