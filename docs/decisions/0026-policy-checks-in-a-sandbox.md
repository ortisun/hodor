# Decision 0026: Policies are checked by the `opa` binary, run by the worker as a child process with nothing of its own

Status: Accepted (made for Issue-79; the project owner asked for the policy lifecycle, not for this choice)

## Context

[Decision 0010](0010-opa-integration.md) says that a policy is validated and tested with the `opa` binary in a sandboxed worker job, and leaves the mechanism to a spike. A policy has to pass three things before it is published, and the same program has to answer all three:

- it compiles, in strict mode, against [the capabilities file](../architecture/contexts/authorization.md#the-capabilities-file), `deploy/open-policy-agent/capabilities.json`, so no removed built-in is used;
- its tests pass;
- a simulation evaluates it against requests given by whoever wrote it.

A Rust implementation of Rego would not do: it is not the program the instances run, and a policy that passes one and fails the other is a policy that was not checked. So the question is only where `opa` runs and what holds it in.

The ways that were looked at:

| | Child process of the worker | A container started per check | A validation service next to the worker |
|---|---|---|---|
| What the worker needs | The binary in its image | A container runtime it may command: the Docker socket, or a Kubernetes service account that creates pods | An address, and a second deployment |
| What a check can reach | What the worker's process can, unless the policy is refused first | Nothing, with `--network none` | What the service can |
| Isolation of memory and time | A time limit and Go's memory limit; the container's own limits as the hard bound | The runtime's limits | The service's |
| Cost | 46 megabytes more in the image, one process per check | Commanding a runtime is a far larger power than checking a policy | One more thing to deploy, secure and upgrade |

The `opa` 1.10.1 binary in `openpolicyagent/opa:1.10.1-static` is the release binary, the same file as `opa_linux_amd64_static` and `opa_linux_arm64_static` with the checksums the project publishes, and needs nothing from the system.

## Decision

- **The worker runs `opa` as a child process**, through the `PolicyChecker` port, implemented by a new adapter, `hodor-adapters-policy-check`. Three commands, always with Hodor's capabilities file, which the adapter carries in its own code, so that it cannot differ from the file it was built with:
  - `opa check --strict --capabilities …` to validate;
  - `opa test --capabilities …` to test;
  - `opa eval --capabilities …` over a module of Hodor's own to simulate, one process for every request of a simulation.
- **What holds a check in:**
  - **No network by construction.** The only built-ins that reach the network, `http.send` and `net.lookup_ip_addr`, are not in the capabilities file. A module that calls them does not compile, in a check, a test or a simulation. Everything the process loads is a file it was given; no remote bundle, no schema from an address. The worker should still have no route out of its network beyond what it needs, as the operations documents say.
  - **Nothing of the worker's.** Each run gets a new directory of its own, readable by its owner only, with the version's files and nothing else, which is removed afterwards. The process starts with an empty environment except `HOME`, set to that directory, `GOMEMLIMIT` and `GOMAXPROCS`. It gets no standard input. Its working directory is the run's directory.
  - **Bounded.** Each run has a time limit, 30 seconds by default, after which the process is killed and the version is refused for taking too long. At most 1 mebibyte of what it prints is read. `GOMEMLIMIT` asks the Go runtime to stay under 256 mebibytes. The hard bound on memory is the worker container's own limit, which the chart sets.
- **The binary comes with the image.** The image copies `/opa` from `openpolicyagent/opa:1.10.1-static`, pinned by digest, and the build refuses the file unless its SHA-256 is the published checksum for the architecture. At startup the worker refuses a binary that does not report version 1.10.1, and, when `HODOR_OPEN_POLICY_AGENT_BINARY_SHA256` is set, one whose SHA-256 differs.
- **Without the binary, nothing is published.** A worker started without `HODOR_OPEN_POLICY_AGENT_BINARY` checks nothing and says so at startup; versions wait to be checked, and only a tested version can be published.
- **A failure to run is not a refusal.** When the binary cannot be started, the version is left as it was and checked on a later pass; it is refused only for what the policy did: a compile error, a failing test, too long a run.

## Consequences

- The image grows by 46 megabytes, from about 96 to about 142. The server and the command-line tool carry a binary they never run, because there is one image.
- An upgrade of Open Policy Agent changes three pinned things together: the image of the instances, the image the binary is copied from with its checksums, and the capabilities file.
- A policy that would reach the network is refused at the first check, so no step of the lifecycle ever runs one.
- The child process shares the worker's user and kernel. A flaw in `opa` that let a policy escape its built-ins would run with the worker's rights; the capabilities file and the container's limits are the defense, not a kernel boundary.

## Alternatives considered

- **A container per check.** The strongest isolation, but it hands the worker the power to start containers, which is the power to run anything on the host. A check would then be safer than the worker that runs it.
- **A validation service.** It isolates the checks from the worker but not from each other, and adds a deployment with a network interface to protect. Worth it when checks need more memory than a worker should have.
- **Seccomp, namespaces or resource limits set in the child before it runs.** They need code that runs between `fork` and `exec`, which the workspace's ban on `unsafe` does not allow, and privileges a distroless container does not have.
- **A Rego implementation in Rust.** Not the program the instances run; see the context above.
