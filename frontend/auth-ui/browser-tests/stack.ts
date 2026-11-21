// Where the stack under test is, and a check that it is there before any
// test starts.

export const SERVER = process.env["HODOR_URL"] ?? "http://localhost:8080";
export const MAIL = process.env["HODOR_MAIL_URL"] ?? "http://localhost:8025";
export const TENANT = process.env["HODOR_TENANT"] ?? "acme";

const HELP = `
The browser tests need the development stack and a tenant that accepts registrations:

  docker compose -f deploy/docker/compose.yaml up --build --wait
  docker compose -f deploy/docker/compose.yaml run --rm --entrypoint /usr/local/bin/hodor-cli \\
    -e HODOR_DATABASE_URL=postgres://hodor_server:dev-server@postgres:5432/hodor \\
    server tenant create --slug ${TENANT} --name "Acme" --open-registration

Set HODOR_URL, HODOR_MAIL_URL or HODOR_TENANT if yours are elsewhere.`;

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
}
