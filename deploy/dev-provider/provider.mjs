// A development identity provider. NOT FOR ANYTHING REAL.
//
// It speaks enough OpenID Connect for Hodor to sign people in through it,
// and it lets anyone sign in as anyone: the "sign-in page" asks who you
// would like to be. It exists so that the development stack, the browser
// tests and the demonstration have a provider to talk to.
//
// One file, no dependencies: Node.js and its standard library.
// See docs/development/local-setup.md.

import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { createServer } from "node:http";

const PORT = Number(process.env.PORT ?? 9400);
// What the provider calls itself, and where Hodor reaches it.
const ISSUER = process.env.ISSUER ?? `http://provider:${PORT}`;
// Where a person's browser reaches it.
const BROWSER_URL = process.env.BROWSER_URL ?? `http://localhost:${PORT}`;
const CLIENT_ID = process.env.CLIENT_ID ?? "hodor";
const CLIENT_SECRET = process.env.CLIENT_SECRET ?? "development-client-secret";

const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const KEY_ID = "development-key";
const published = { ...publicKey.export({ format: "jwk" }), kid: KEY_ID, use: "sig", alg: "ES256" };

/** Codes waiting to be exchanged: used once, good for a minute. */
const codes = new Map();

const base64url = (value) => Buffer.from(value).toString("base64url");

function idToken(claims) {
  const header = base64url(JSON.stringify({ alg: "ES256", typ: "JWT", kid: KEY_ID }));
  const body = base64url(JSON.stringify(claims));
  const signature = sign("sha256", Buffer.from(`${header}.${body}`), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${header}.${body}.${signature.toString("base64url")}`;
}

const escape = (text) =>
  String(text ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escape(title)}</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; margin: 3rem auto; max-width: 26rem; padding: 0 1rem; color: #1a1d23; background: #f6f7f9; }
  main { background: #fff; border: 1px solid #d5d9e0; border-radius: 8px; padding: 1.5rem; }
  h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
  .warning { background: #fff4d6; border: 1px solid #e0b93a; border-radius: 6px; padding: .5rem .75rem; font-size: .875rem; }
  label { display: block; font-weight: 600; font-size: .875rem; margin-top: 1rem; }
  input[type=text], input[type=email] { box-sizing: border-box; width: 100%; padding: .5rem; font: inherit; border: 1px solid #8a93a3; border-radius: 4px; }
  .check { display: flex; align-items: center; gap: .5rem; font-weight: 400; }
  .actions { display: flex; gap: .5rem; margin-top: 1.5rem; }
  button { font: inherit; padding: .5rem 1rem; border-radius: 6px; border: 1px solid #8a93a3; background: #fff; cursor: pointer; }
  button[value=allow] { background: #0b6f8a; border-color: #0b6f8a; color: #fff; }
</style>
</head>
<body><main>${body}</main></body>
</html>`;
}

function send(response, status, headers, body) {
  response.writeHead(status, { "cache-control": "no-store", ...headers });
  response.end(body);
}

const json = (response, status, value) =>
  send(response, status, { "content-type": "application/json" }, JSON.stringify(value));

async function form(request) {
  let text = "";
  for await (const chunk of request) {
    text += chunk;
    if (text.length > 64 * 1024) {
      throw new Error("too large");
    }
  }
  return new URLSearchParams(text);
}

function authorize(url, response) {
  const query = url.searchParams;
  if (query.get("client_id") !== CLIENT_ID || query.get("response_type") !== "code") {
    return send(response, 400, { "content-type": "text/plain" }, "unknown client or response type");
  }
  const hidden = ["redirect_uri", "state", "nonce", "code_challenge", "code_challenge_method"]
    .map((name) => `<input type="hidden" name="${name}" value="${escape(query.get(name))}">`)
    .join("");
  send(
    response,
    200,
    { "content-type": "text/html; charset=utf-8" },
    page(
      "Development provider",
      `<h1>Development provider</h1>
<p class="warning">This provider lets anyone sign in as anyone. It is for development only.</p>
<form method="post" action="/authorize/decision">
${hidden}
<label for="subject">Subject</label>
<input type="text" id="subject" name="subject" value="development-subject" required>
<label for="email">Email address</label>
<input type="email" id="email" name="email" value="person@example.com">
<label class="check"><input type="checkbox" name="email_verified" value="true" checked> The provider vouches for this address</label>
<label for="name">Name</label>
<input type="text" id="name" name="name" value="Development Person">
<div class="actions">
<button type="submit" name="decision" value="allow">Sign in</button>
<button type="submit" name="decision" value="deny">Cancel</button>
</div>
</form>`,
    ),
  );
}

async function decide(request, response) {
  const sent = await form(request);
  let back;
  try {
    back = new URL(sent.get("redirect_uri") ?? "");
  } catch {
    return send(response, 400, { "content-type": "text/plain" }, "no address to go back to");
  }
  if (sent.get("state")) {
    back.searchParams.set("state", sent.get("state"));
  }
  if (sent.get("decision") !== "allow") {
    back.searchParams.set("error", "access_denied");
    return send(response, 303, { location: back.toString() }, "");
  }
  const code = randomBytes(24).toString("base64url");
  codes.set(code, {
    expires: Date.now() + 60_000,
    redirect_uri: sent.get("redirect_uri"),
    challenge: sent.get("code_challenge"),
    claims: {
      sub: sent.get("subject") || "development-subject",
      nonce: sent.get("nonce") ?? undefined,
      email: sent.get("email") || undefined,
      email_verified: sent.get("email") ? sent.get("email_verified") === "true" : undefined,
      name: sent.get("name") || undefined,
    },
  });
  back.searchParams.set("code", code);
  send(response, 303, { location: back.toString() }, "");
}

function clientOf(request, sent) {
  const header = request.headers.authorization ?? "";
  if (header.startsWith("Basic ")) {
    const [id, secret] = Buffer.from(header.slice(6), "base64").toString().split(":");
    const plain = (part) => new URLSearchParams(`x=${part}`).get("x");
    return { id: plain(id), secret: plain(secret ?? "") };
  }
  return { id: sent.get("client_id"), secret: sent.get("client_secret") };
}

async function token(request, response) {
  const sent = await form(request);
  const client = clientOf(request, sent);
  if (client.id !== CLIENT_ID || client.secret !== CLIENT_SECRET) {
    return json(response, 401, { error: "invalid_client" });
  }
  const code = sent.get("code") ?? "";
  const kept = codes.get(code);
  // Whatever happens next, the code is gone.
  codes.delete(code);
  const challenge = createHash("sha256").update(sent.get("code_verifier") ?? "").digest("base64url");
  if (
    sent.get("grant_type") !== "authorization_code" ||
    kept === undefined ||
    kept.expires < Date.now() ||
    kept.redirect_uri !== sent.get("redirect_uri") ||
    kept.challenge !== challenge
  ) {
    return json(response, 400, { error: "invalid_grant" });
  }
  const now = Math.floor(Date.now() / 1000);
  json(response, 200, {
    token_type: "Bearer",
    access_token: randomBytes(16).toString("base64url"),
    expires_in: 60,
    id_token: idToken({ iss: ISSUER, aud: CLIENT_ID, iat: now, exp: now + 300, ...kept.claims }),
  });
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", "http://provider");
  try {
    const route = `${request.method} ${url.pathname}`;
    switch (route) {
      case "GET /health":
        return send(response, 200, { "content-type": "text/plain" }, "ok");
      case "GET /.well-known/openid-configuration":
        return json(response, 200, {
          issuer: ISSUER,
          authorization_endpoint: `${BROWSER_URL}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/keys`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["ES256"],
          token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
          code_challenge_methods_supported: ["S256"],
        });
      case "GET /keys":
        return json(response, 200, { keys: [published] });
      case "GET /authorize":
        return authorize(url, response);
      case "POST /authorize/decision":
        return await decide(request, response);
      case "POST /token":
        return await token(request, response);
      default:
        return send(response, 404, { "content-type": "text/plain" }, "not found");
    }
  } catch (error) {
    console.error(error);
    send(response, 500, { "content-type": "text/plain" }, "the development provider failed");
  }
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}

server.listen(PORT, () => {
  console.log(
    `development identity provider: issuer ${ISSUER}, browser ${BROWSER_URL}. It lets anyone sign in as anyone.`,
  );
});
