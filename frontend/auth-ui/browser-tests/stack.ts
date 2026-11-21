// Where the stack under test is, and a check that it is there before any
// test starts.

export const SERVER = process.env["HODOR_URL"] ?? "http://localhost:8080";
export const MAIL = process.env["HODOR_MAIL_URL"] ?? "http://localhost:8025";
export const TENANT = process.env["HODOR_TENANT"] ?? "acme";
/** The alias of the development identity provider in that tenant. */
export const PROVIDER = process.env["HODOR_PROVIDER"] ?? "development";
/** The alias of the development directory in that tenant. */
export const DIRECTORY = process.env["HODOR_DIRECTORY"] ?? "directory";

const HELP = `
The browser tests need the development stack and a tenant that accepts registrations:

  docker compose -f deploy/docker/compose.yaml up --build --wait
  docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli \\
    -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor \\
    server tenant create --slug ${TENANT} --name "Acme" --open-registration

and the development identity provider added to that tenant:

  docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli \\
    -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor \\
    -e HODOR_PROVIDER_CLIENT_SECRET=development-client-secret \\
    server provider add --tenant ${TENANT} --alias ${PROVIDER} --name "Development provider" \\
    --issuer http://provider:9400 --client-id hodor

and the development directory:

  docker compose -f deploy/docker/compose.yaml run --rm --no-deps --entrypoint /usr/local/bin/hodor-cli \\
    -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor \\
    -e HODOR_PROVIDER_CLIENT_SECRET=readonly-password \\
    server provider add --tenant ${TENANT} --alias ${DIRECTORY} --kind ldap --name "Company directory" \\
    --issuer ldap://directory:389 --client-id cn=readonly,dc=example,dc=org \\
    --base ou=people,dc=example,dc=org --filter "(uid={identifier})" --trust-email

Set HODOR_URL, HODOR_MAIL_URL, HODOR_TENANT, HODOR_PROVIDER or HODOR_DIRECTORY if yours are elsewhere.`;

export default async function checkTheStack(): Promise<void> {
  const page = `${SERVER}/t/${TENANT}/account/sign-in`;
  const answers = await Promise.all(
    [page, `${MAIL}/api/v1/info`].map((address) =>
      fetch(address).then(
        (response) => response.status,
        () => 0,
      ),
    ),
  );
  if (answers[0] !== 200) {
    throw new Error(`${page} answered ${answers[0]}, not 200.${HELP}`);
  }
  if (answers[1] !== 200) {
    throw new Error(`The development mail server at ${MAIL} did not answer.${HELP}`);
  }
  const offered = await fetch(`${SERVER}/t/${TENANT}/interaction/sign-in/providers`).then(
    (response) => response.json() as Promise<{ providers: { alias: string }[] }>,
    () => ({ providers: [] }),
  );
  for (const alias of [PROVIDER, DIRECTORY]) {
    if (!offered.providers.some((provider) => provider.alias === alias)) {
      throw new Error(`The tenant ${TENANT} does not offer the identity provider ${alias}.${HELP}`);
    }
  }

  // Asking for links is limited by the address the requests come from,
  // and every run asks for about ten. Run after run, a tenant refuses.
  const asked = await fetch(`${SERVER}/t/${TENANT}/interaction/recovery`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: `nobody-${Date.now()}@example.com` }),
  });
  if (asked.status === 429) {
    throw new Error(
      `The tenant ${TENANT} is limiting requests from this address after too many runs in a row. ` +
        `Wait ${asked.headers.get("Retry-After") ?? "some"} seconds, or create another tenant ` +
        `with open registration and name it in HODOR_TENANT.`,
    );
  }
}
