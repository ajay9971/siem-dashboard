// Plain Node server for Render (no npm packages needed). Serves the dashboard and the two API routes.
const http = require("http"), fs = require("fs"), path = require("path");
const routes = { "/api/ingest": require("./api/ingest"), "/api/logs": require("./api/logs") };

http.createServer(async (req, res) => {
  res.status = c => { res.statusCode = c; return res; };
  res.send = t => res.end(t);
  res.json = o => { res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify(o)); };
  const url = req.url.split("?")[0], handler = routes[url];
  if (handler) {
    let body = "";
    for await (const c of req) body += c;
    try { req.body = body ? JSON.parse(body) : {}; } catch (_) { req.body = {}; }
    return handler(req, res);
  }
  if (url === "/" || url === "/index.html") {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.end(fs.readFileSync(path.join(__dirname, "index.html")));
  }
  res.statusCode = 404; res.end("Not found");
}).listen(process.env.PORT || 3000, () => console.log("SIEM running on port " + (process.env.PORT || 3000)));
