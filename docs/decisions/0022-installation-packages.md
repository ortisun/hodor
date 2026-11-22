# Decision 0022: Hodor is installed from two packages kept apart from the development stack, and neither holds a secret

Status: Proposed (the packages were requested by the project owner; the choices here wait for their review)

## Context

Until now the only way to start Hodor was the development stack in `deploy/docker`. It exists to work on Hodor and to run the demonstrations: its passwords and its encryption key are written in the repository, it starts identity providers that let anyone sign in as anyone, and it allows plain HTTP to private addresses. [The quick-start](../operations/quick-start.md#before-anything-real) lists what must change before anything real, and leaves the changing to the reader.

The owner asked for installation packages: one for Docker alone and one for Kubernetes, the second as a Helm chart. [Deployment](../operations/deployment.md) already describes the chart Hodor is heading for.

What the packages must respect:

- **No secret in the repository, in an image or in chart values** ([deployment](../operations/deployment.md#configuration-and-secrets)).
- **Only the migrations connect as the owner of the schema** ([database roles](../development/local-setup.md#database-roles)).
- **The migrations run before the code that needs them**, and never from the server ([upgrades](../operations/deployment.md#upgrades)).
- **Nothing is described as done that is not.** Hodor has known gaps, and a package must not hide them.

## Decision

- **Two packages, in `deploy/install/`, separate from `deploy/docker/`**: `docker/`, a Compose file for one machine, and `helm/hodor/`, a chart. They share the image and nothing else with the development stack, and the Compose project has its own name, `hodor-install`, so that the two never share a container or a volume on one machine.
- **Neither package has a default secret.** The Compose file reads every password and key from a file `.env` that git ignores, and refuses to start while a required value is missing. The chart takes no secret as a value at all: it reads one Secret, by name, that exists before the chart is installed.
- **The database and HTTPS are optional parts of the Docker package, and no part of the chart.** On one machine, a PostgreSQL container and a web server that gets its own certificate are what most people lack, so they are Compose profiles, on by default and removable. On a cluster, the database is a managed service and the way in is the cluster's own, so the chart creates neither.
- **In the chart, the migrations and the system tenant are one Helm hook** that runs before every install and upgrade: `hodor-cli migrate` with the owner's address, then `hodor-cli tenant create-system` with the server's. Because the Secret is not part of the release, it exists when the hook runs for the first time.
- **Trying the chart is a file beside it, not a switch inside it.** `deploy/install/helm/evaluation.yaml` holds a PostgreSQL, a mail server that delivers nothing and the Secret, with passwords written in the repository and said to be so. A chart that could create its own database would need two orders of installation and a secret made by the chart.
- **Each package's page says what it does not do yet**, next to how to use it.

How to use them is in [installing with Docker](../operations/install-with-docker.md) and [installing on Kubernetes](../operations/install-on-kubernetes.md).

## Consequences

- Someone can start Hodor with passwords of their own, HTTPS and no development provider by following one page, on one machine or on a cluster.
- The image is still built from a checkout: no registry publishes it, and the chart is installed from the checkout too. Publishing both, with a software bill of materials and signatures, remains to be done.
- **Hodor is always behind a web server in both packages**, because it does not serve HTTPS itself. The limit on sign-in attempts counts by the address of the connection, so everyone shares one limit until Hodor trusts a forwarded address from named proxies. Both pages say so.
- Continuous integration checks that the chart renders and that the Compose file is valid. It does not install either: that was done by hand, on one machine and on a local cluster, when the packages were written.
- A change to a setting of the binaries, to the roles or to the order of starting now has three places to follow it: the development stack and the two packages.

## Alternatives considered

| Alternative | Why not |
|---|---|
| One Compose file for development and installation, with profiles | The development stack needs public passwords and the setting that allows plain HTTP to private addresses. One mistaken profile would carry them into an installation |
| Secrets as chart values | They end up in the history of the release, in files of values and in whatever renders the chart. The documentation already forbids it |
| A PostgreSQL inside the chart, as a dependency or a switch | The hook that migrates before installing would run before that database exists, and its passwords would be made by the chart. A real installation uses a managed database |
| The migrations as an init container of the server | Every server pod would hold the owner's password, and the server would no longer be unable to change the schema |
| Kustomize or plain manifests in place of Helm | The owner asked for Helm, and the hook that orders the migrations before an upgrade is what Helm gives |
