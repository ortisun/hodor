// A development SAML identity provider. NOT FOR ANYTHING REAL.
//
// It answers Hodor's requests with signed responses, and it lets anyone
// sign in as anyone: its sign-in page asks who you would like to be. Its
// signing key is written in the repository, beside it. It exists so that
// the development stack, the browser tests and the demonstration have a
// SAML identity provider to talk to.
//
// One file, no dependencies: Node.js and its standard library. It writes
// its assertions already in the exclusive canonical form, so that it can
// sign them without an XML library: what it signs is exactly the text it
// sends. See docs/development/local-setup.md.

import { createHash, randomBytes, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { inflateRawSync } from "node:zlib";

const PORT = Number(process.env.PORT ?? 9500);
// What the identity provider calls itself: the issuer of what it sends.
const ENTITY_ID = process.env.ENTITY_ID ?? "urn:hodor:development-saml-provider";
// Where a person's browser reaches it.
const BROWSER_URL = process.env.BROWSER_URL ?? `http://localhost:${PORT}`;
const here = new URL(".", import.meta.url);
const KEY = readFileSync(process.env.KEY_FILE ?? new URL("signing-key.pem", here), "utf8");
const CERTIFICATE = readFileSync(process.env.CERTIFICATE_FILE ?? new URL("certificate.pem", here), "utf8");
const CERTIFICATE_BASE64 = CERTIFICATE.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");

const PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
const SIGNATURE = "http://www.w3.org/2000/09/xmldsig#";
const EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#";

// Escaping as canonical XML writes it: text, and attribute values.
const text = (value) =>
  String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\r/g, "&#xD;");
const attribute = (value) =>
  String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/"/g, "&quot;")
    .replace(/\t/g, "&#x9;")
    .replace(/\n/g, "&#xA;")
    .replace(/\r/g, "&#xD;");
// Escaping for the HTML pages.
const html = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const instant = (milliseconds) => new Date(milliseconds).toISOString().replace(/\.\d{3}Z$/, "Z");
const identifier = () => `_${randomBytes(20).toString("hex")}`;

/**
 * A signed response to one request. Attributes are written in the order
 * canonical XML sorts them, empty elements as a start and an end tag, and
 * every namespace on the element that first uses it: the assertion's text
 * is its own canonical form.
 */
function signedResponse({ request, subject, email, name }) {
  const now = Date.now();
  const assertionId = identifier();
  const issued = instant(now);
  const until = instant(now + 5 * 60_000);
  const parts = {
    open: `<saml:Assertion xmlns:saml="${ASSERTION}" ID="${assertionId}" IssueInstant="${issued}" Version="2.0">`,
    issuer: `<saml:Issuer>${text(ENTITY_ID)}</saml:Issuer>`,
    rest:
      `<saml:Subject>` +
      `<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${text(subject)}</saml:NameID>` +
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
      `<saml:SubjectConfirmationData InResponseTo="${attribute(request.id)}" NotOnOrAfter="${until}" Recipient="${attribute(request.consumer)}"></saml:SubjectConfirmationData>` +
      `</saml:SubjectConfirmation></saml:Subject>` +
      `<saml:Conditions NotBefore="${instant(now - 30_000)}" NotOnOrAfter="${until}">` +
      `<saml:AudienceRestriction><saml:Audience>${text(request.audience)}</saml:Audience></saml:AudienceRestriction>` +
      `</saml:Conditions>` +
      `<saml:AuthnStatement AuthnInstant="${issued}" SessionIndex="${identifier()}">` +
      `<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext>` +
      `</saml:AuthnStatement>` +
      `<saml:AttributeStatement>` +
      `<saml:Attribute Name="email"><saml:AttributeValue>${text(email)}</saml:AttributeValue></saml:Attribute>` +
      `<saml:Attribute Name="name"><saml:AttributeValue>${text(name)}</saml:AttributeValue></saml:Attribute>` +
      `</saml:AttributeStatement>`,
    close: `</saml:Assertion>`,
  };
  // The enveloped signature is left out of what is digested.
  const digest = createHash("sha256")
    .update(parts.open + parts.issuer + parts.rest + parts.close)
    .digest("base64");
  const signedInfo =
    `<ds:SignedInfo xmlns:ds="${SIGNATURE}">` +
    `<ds:CanonicalizationMethod Algorithm="${EXCLUSIVE}"></ds:CanonicalizationMethod>` +
    `<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>` +
    `<ds:Reference URI="#${assertionId}"><ds:Transforms>` +
    `<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>` +
    `<ds:Transform Algorithm="${EXCLUSIVE}"></ds:Transform>` +
    `</ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
    `<ds:DigestValue>${digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>`;
  const value = sign("sha256", Buffer.from(signedInfo), KEY).toString("base64");
  // In the document the namespace is declared on the signature; the
  // canonical form of the signed information declares it there instead.
  const signature =
    `<ds:Signature xmlns:ds="${SIGNATURE}">` +
    signedInfo.replace(` xmlns:ds="${SIGNATURE}"`, "") +
    `<ds:SignatureValue>${value}</ds:SignatureValue>` +
    `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>${CERTIFICATE_BASE64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>` +
    `</ds:Signature>`;
  const assertion = parts.open + parts.issuer + signature + parts.rest + parts.close;
  return samlResponse(request, "urn:oasis:names:tc:SAML:2.0:status:Success", assertion);
}

function samlResponse(request, status, assertion) {
  return (
    `<samlp:Response xmlns:samlp="${PROTOCOL}" xmlns:saml="${ASSERTION}" Destination="${attribute(request.consumer)}" ` +
    `ID="${identifier()}" InResponseTo="${attribute(request.id)}" IssueInstant="${instant(Date.now())}" Version="2.0">` +
    `<saml:Issuer>${text(ENTITY_ID)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="${status}"></samlp:StatusCode></samlp:Status>` +
    assertion +
    `</samlp:Response>`
  );
}

/** What Hodor asked for, read from the HTTP-Redirect binding. */
function requestOf(encoded) {
  const xml = inflateRawSync(Buffer.from(encoded, "base64"), { maxOutputLength: 64 * 1024 }).toString("utf8");
  const read = (pattern) => xml.match(pattern)?.[1];
  const request = {
    id: read(/\sID="([^"]+)"/),
    consumer: read(/\sAssertionConsumerServiceURL="([^"]+)"/),
    audience: read(/<saml:Issuer>([^<]+)<\/saml:Issuer>/),
  };
  if (!request.id || !request.consumer?.match(/^https?:\/\//) || !request.audience) {
    throw new Error("not a request this provider understands");
  }
  return request;
}

function page(title, body, extra = "") {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${html(title)}</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; margin: 3rem auto; max-width: 26rem; padding: 0 1rem; color: #1a1d23; background: #f6f7f9; }
  main { background: #fff; border: 1px solid #d5d9e0; border-radius: 8px; padding: 1.5rem; }
  h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
  .warning { background: #fff4d6; border: 1px solid #e0b93a; border-radius: 6px; padding: .5rem .75rem; font-size: .875rem; }
  label { display: block; font-weight: 600; font-size: .875rem; margin-top: 1rem; }
  input[type=text], input[type=email] { box-sizing: border-box; width: 100%; padding: .5rem; font: inherit; border: 1px solid #8a93a3; border-radius: 4px; }
  .actions { display: flex; gap: .5rem; margin-top: 1.5rem; }
  button { font: inherit; padding: .5rem 1rem; border-radius: 6px; border: 1px solid #8a93a3; background: #fff; cursor: pointer; }
  button[value=allow], button.go { background: #0b6f8a; border-color: #0b6f8a; color: #fff; }
</style>
</head>
<body><main>${body}</main>${extra}</body>
</html>`;
}

function send(response, status, headers, body) {
  response.writeHead(status, { "cache-control": "no-store", ...headers });
  response.end(body);
}

const htmlPage = (response, body) => send(response, 200, { "content-type": "text/html; charset=utf-8" }, body);

async function form(request) {
  let sent = "";
  for await (const chunk of request) {
    sent += chunk;
    if (sent.length > 64 * 1024) {
      throw new Error("too large");
    }
  }
  return new URLSearchParams(sent);
}

function signOn(url, response) {
  let request;
  try {
    request = requestOf(url.searchParams.get("SAMLRequest") ?? "");
  } catch {
    return send(response, 400, { "content-type": "text/plain" }, "not a request this provider understands");
  }
  const hidden = {
    request_id: request.id,
    consumer: request.consumer,
    audience: request.audience,
    relay_state: url.searchParams.get("RelayState") ?? "",
  };
  const fields = Object.entries(hidden)
    .map(([name, value]) => `<input type="hidden" name="${name}" value="${html(value)}">`)
    .join("");
  htmlPage(
    response,
    page(
      "Development SAML provider",
      `<h1>Development SAML provider</h1>
<p class="warning">This identity provider lets anyone sign in as anyone. It is for development only.</p>
<form method="post" action="/sso/decision">
${fields}
<label for="subject">Name identifier</label>
<input type="text" id="subject" name="subject" value="development-saml-subject" required>
<label for="email">Email address</label>
<input type="email" id="email" name="email" value="saml-person@example.com">
<label for="name">Name</label>
<input type="text" id="name" name="name" value="Development SAML Person">
<div class="actions">
<button type="submit" name="decision" value="allow">Sign in</button>
<button type="submit" name="decision" value="deny">Cancel</button>
</div>
</form>`,
    ),
  );
}

async function decide(incoming, response) {
  const sent = await form(incoming);
  const request = {
    id: sent.get("request_id") ?? "",
    consumer: sent.get("consumer") ?? "",
    audience: sent.get("audience") ?? "",
  };
  if (!request.id || !request.consumer.match(/^https?:\/\//) || !request.audience) {
    return send(response, 400, { "content-type": "text/plain" }, "the request is incomplete");
  }
  const xml =
    sent.get("decision") === "allow"
      ? signedResponse({
          request,
          subject: sent.get("subject") || "development-saml-subject",
          email: sent.get("email") || "saml-person@example.com",
          name: sent.get("name") || "Development SAML Person",
        })
      : // Cancelled: a response that says so, with no assertion.
        samlResponse(request, "urn:oasis:names:tc:SAML:2.0:status:Responder", "");
  // The browser posts the response to Hodor, as the HTTP-POST binding says.
  htmlPage(
    response,
    page(
      "Development SAML provider",
      `<h1>Back to Hodor</h1>
<form method="post" action="${html(request.consumer)}">
<input type="hidden" name="SAMLResponse" value="${html(Buffer.from(xml).toString("base64"))}">
<input type="hidden" name="RelayState" value="${html(sent.get("relay_state") ?? "")}">
<div class="actions"><button type="submit" class="go">Continue</button></div>
</form>`,
      "<script>document.forms[0].submit();</script>",
    ),
  );
}

function metadata(response) {
  send(
    response,
    200,
    { "content-type": "application/samlmetadata+xml" },
    `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${attribute(ENTITY_ID)}">` +
      `<md:IDPSSODescriptor protocolSupportEnumeration="${PROTOCOL}">` +
      `<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="${SIGNATURE}"><ds:X509Data><ds:X509Certificate>${CERTIFICATE_BASE64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
      `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${attribute(`${BROWSER_URL}/sso`)}"/>` +
      `</md:IDPSSODescriptor></md:EntityDescriptor>`,
  );
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", "http://saml-provider");
  try {
    switch (`${request.method} ${url.pathname}`) {
      case "GET /health":
        return send(response, 200, { "content-type": "text/plain" }, "ok");
      case "GET /metadata":
        return metadata(response);
      case "GET /sso":
        return signOn(url, response);
      case "POST /sso/decision":
        return await decide(request, response);
      default:
        return send(response, 404, { "content-type": "text/plain" }, "not found");
    }
  } catch (error) {
    console.error(error);
    send(response, 500, { "content-type": "text/plain" }, "the development SAML provider failed");
  }
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}

server.listen(PORT, () => {
  console.log(`development SAML identity provider: ${ENTITY_ID}. It lets anyone sign in as anyone.`);
});
