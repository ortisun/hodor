// A development receiver of webhooks. NOT FOR ANYTHING REAL.
//
// It answers every POST with 204 and keeps what it got, so that the
// development stack and the demonstrations of Milestones 8 and 9 have an
// endpoint Hodor can deliver webhooks and logout tokens to. It checks
// nothing: checking a delivery's signature is the part of the receiver the
// demonstrations play themselves.
//
// It also keeps what a PUT gives it and answers it to every GET of the same
// path, so that the demonstration of Milestone 13 has a client's address
// for request objects that Hodor can fetch, and it remembers each such GET.
//
// One file, no dependencies: Node.js and its standard library.
// See docs/development/local-setup.md.

import { createServer } from "node:http";

const PORT = Number(process.env.PORT ?? 9600);
// How many deliveries are kept, the oldest forgotten first.
const KEPT = 500;
// The largest body kept; Hodor sends at most 64 kibibytes.
const LARGEST = 128 * 1024;

/** What was received, oldest first. */
const received = [];
/** What a PUT gave, by path, answered to every GET of that path. */
const kept = new Map();
/** The GETs of what a PUT gave, oldest first. */
const fetched = [];

const HEADERS = ["content-type", "webhook-id", "webhook-timestamp", "webhook-signature"];

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(JSON.stringify(body));
}

function read(request) {
  return new Promise((resolve, reject) => {
    const parts = [];
    let size = 0;
    request.on("data", (part) => {
      size += part.length;
      if (size > LARGEST) {
        reject(new Error("too large"));
        request.destroy();
        return;
      }
      parts.push(part);
    });
    request.on("end", () => resolve(Buffer.concat(parts).toString("utf8")));
    request.on("error", reject);
  });
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", "http://receiver");
  try {
    if (request.method === "GET" && url.pathname === "/health") {
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("ok");
      return;
    }
    if (request.method === "GET" && url.pathname === "/received") {
      const path = url.searchParams.get("path");
      const id = url.searchParams.get("webhook-id");
      const items = received.filter(
        (item) => (path === null || item.path === path) && (id === null || item.headers["webhook-id"] === id),
      );
      json(response, 200, { items });
      return;
    }
    if (request.method === "GET" && url.pathname === "/fetched") {
      const path = url.searchParams.get("path");
      json(response, 200, { items: fetched.filter((item) => path === null || item.path === path) });
      return;
    }
    if (request.method === "PUT") {
      const body = await read(request);
      kept.delete(url.pathname);
      kept.set(url.pathname, body);
      if (kept.size > KEPT) {
        kept.delete(kept.keys().next().value);
      }
      response.writeHead(204);
      response.end();
      return;
    }
    if (request.method === "GET" && kept.has(url.pathname)) {
      fetched.push({ path: url.pathname, accept: request.headers.accept ?? null, fetched_at: new Date().toISOString() });
      if (fetched.length > KEPT) {
        fetched.shift();
      }
      response.writeHead(200, { "content-type": "application/oauth-authz-req+jwt", "cache-control": "no-store" });
      response.end(kept.get(url.pathname));
      return;
    }
    if (request.method === "POST") {
      const body = await read(request);
      const headers = Object.fromEntries(HEADERS.map((name) => [name, request.headers[name] ?? null]));
      received.push({ path: url.pathname, headers, body, received_at: new Date().toISOString() });
      if (received.length > KEPT) {
        received.shift();
      }
      response.writeHead(204);
      response.end();
      return;
    }
    json(response, 404, { error: "not found" });
  } catch {
    json(response, 413, { error: "too large" });
  }
});

server.listen(PORT, () => {
  console.log(`webhook receiver listening on ${PORT}`);
});
