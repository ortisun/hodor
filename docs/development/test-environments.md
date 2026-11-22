# Test environments

Two environments on one machine, for trying Hodor by hand, for running the browser tests and the demonstrations against something that stays up, and for trying the installation package. Each comes up ready to use: a tenant, a person with a password, an administrator with a token. Each has a name of its own, `hodor-test`, and ports of its own, so it never touches the [development stack](local-setup.md#running-the-development-stack) or anything else running on the machine.

> **Not for anything real.** Every password and key in them is written in the repository, and the identity providers let anyone sign in as anyone. They speak plain HTTP on `localhost`.

| Environment | What runs | For | Script |
|---|---|---|---|
| **Docker** | The [development stack](local-setup.md#running-the-development-stack) as the Compose project `hodor-test`: PostgreSQL, the server, the worker, the mail server, the metrics and traces, and the three development providers | Trying Hodor by hand, with every way of signing in; the browser tests and the demonstrations | `deploy/test-environment/docker.sh` |
| **Kubernetes** | A cluster in Docker, made with [kind](https://kind.sigs.k8s.io/) and named `hodor-test`, with Hodor installed by [its Helm chart](../operations/install-on-kubernetes.md) and the [evaluation stand-ins](../operations/install-on-kubernetes.md#trying-the-chart-on-a-cluster-of-your-own) for the database and the mail server | Trying the installation package as a cluster runs it: the migration job, the server and the worker as deployments, the chart's settings | `deploy/test-environment/kubernetes.sh` |

They need Docker, Python 3 for the seeding, and for Kubernetes also `kind`, `kubectl` and `helm`. Docker needs about 2 gigabytes of memory for the first, 3 for the second.

## What each one holds when it comes up

| What | Docker | Kubernetes |
|---|---|---|
| Hodor | <http://localhost:38080> | <http://localhost:48080> |
| The messages Hodor sends | <http://localhost:38025> | <http://localhost:48025> |
| The tenant, which accepts registrations | `test`: <http://localhost:38080/t/test/account> | `test`: <http://localhost:48080/t/test/account> |
| A person with a password | `tester@example.com`, `test-environment-password` | The same |
| An administrator | The same person, with an access token for [the administration interface](../api/admin-api.md) | The same |
| The development OpenID Connect provider, `development` | Offered on the sign-in page; <http://localhost:39400> | — |
| The development directory, `directory` | `dora`, `dora-directory-password` | — |
| The development SAML identity provider, `corp` | Offered on the sign-in page; <http://localhost:39500> | — |
| Metrics and traces | <http://localhost:38428/vmui>, <http://localhost:31428/select/vmui> | — |

The Kubernetes environment holds Hodor and what the chart needs, not the development providers: they are part of the Compose stack, and the chart is about installing Hodor.

An access token lives for an hour. Both scripts print a new one with `token`.

## The Docker environment

```bash
deploy/test-environment/docker.sh up
```

Builds the image from the checkout, starts the stack, waits until everything is healthy, and seeds it: the tenant, the person, the administrator and the three providers. It prints where everything is, and the administrator's token. Running it again starts what was stopped and seeds only what is missing.

| Command | What it does |
|---|---|
| `up` | Builds, starts and seeds, as above |
| `token` | Prints a new access token for the administrator |
| `status` | Shows what is running |
| `logs` | Follows the logs of the server and the worker |
| `down` | Stops everything and keeps the data |
| `reset` | Removes everything, the data included, and starts again from nothing |
| `demonstrate` | Runs the demonstrations of Milestones 1 and 2 against it |

The browser tests and the demonstrations run against it with the addresses set:

```bash
cd frontend/auth-ui && HODOR_URL=http://localhost:38080 HODOR_MAIL_URL=http://localhost:38025 HODOR_TENANT=test npm run browser-tests
```

```bash
deploy/test-environment/docker.sh demonstrate
```

`demonstrate` runs both demonstrations against the environment, with the addresses and the Compose variables it was started with, since the demonstrations call the command-line tool through Compose.

## The Kubernetes environment

```bash
deploy/test-environment/kubernetes.sh up
```

Creates the cluster if it is not there, builds the image and loads it into the cluster, applies the evaluation stand-ins, installs the chart, forwards the ports above to the cluster, and seeds the tenant, the person and the administrator. The forwarded ports keep working while the script's forwarding processes run; `up` starts them again when they stopped.

| Command | What it does |
|---|---|
| `up` | Creates, installs, forwards and seeds, as above |
| `upgrade` | Builds the image again from the checkout and upgrades the release, to try a change to the code or to the chart |
| `token` | Prints a new access token for the administrator |
| `status` | Shows the pods and the release |
| `down` | Stops forwarding the ports. The cluster keeps running |
| `delete` | Deletes the cluster and everything in it |

`kubectl` is pointed at the cluster as `kind-hodor-test`, for looking around:

```bash
kubectl --context kind-hodor-test --namespace hodor get pods
```

## How the seeding works

`deploy/test-environment/seed.py` does what a person and an operator would do, through the same doors: the command-line tool creates the tenant and the providers and makes the administrator, and the person registers through [the interaction interface](../api/interaction-api.md#registering-and-recovering-a-password), reads the message in the mail server and chooses the password. It reuses the helpers of the [demonstrations](../operations/quick-start.md#the-demonstration), checks every answer, and stops at the first one that is not what it should be. It skips what already exists, so it can run again and again.

What the scripts start, and where they keep the forwarding processes of the Kubernetes environment, is under `deploy/test-environment/.local/`, which git ignores.
