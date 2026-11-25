# containers

## Overview

`hodor-test-containers`: how every integration test starts a container and
finds its ports. Specified in `docs/architecture/testing.md`, "Containers in
tests". Test support only: no workspace crate depends on it in production
code.

## Interface

- `HOST`, `"127.0.0.1"`: the address every port is published on, and the
  one tests reach containers at.
- `start(what, request, ports) -> Started<I>`: starts a container made by
  `request`, with each of `ports` published on `HOST` at a port Docker
  chooses, and waits until Docker gives every one. `request` is called once
  per container started.
- `start_checked(what, request, ports, check) -> (Started<I>, T)`: the same,
  then runs `check` on the container, such as a first connection, and
  answers what it made.
- `Started<I>`: `port(inside)`, the port of `HOST` a port of the container
  is published on; `container()`; `into_container()`. The container is
  removed when the value is dropped.

## Invariants

- Only the ports asked for are published, on `HOST` alone
  (`publish_all_ports` off, one `port_bindings` entry each, through
  `with_host_config_modifier`): a port of `127.0.0.1` cannot be shared with
  a process of the machine, so a start that finds it taken fails instead of
  sending the test's connections to that process.
- The ports are read until every one is given, for up to thirty seconds,
  every tenth of a second. A container that is not running is reported with
  its exit code and the last thirty lines it wrote.
- At most three containers are started: a failed start, a container that
  stopped before its ports were given, one whose ports were not given in
  time, or a failed `check` starts another. Then it panics with the reason
  each one failed, naming `what`.
- It does not wait for the program in the container to answer, except
  through `check`: each test does, as it knows how.

## Side Effects

- Creates, starts and removes Docker containers through `testcontainers`.

## Verification

- Used by `cargo test -p hodor-adapters-postgres`, `-p hodor-adapters-ldap`,
  `-p hodor-adapters-smtp --test delivery`, `-p hodor-adapters-kms`,
  `-p hodor-observability`, `-p hodor-authorization-opa --test
  open_policy_agent`, `-p hodor-protocol-http --test policy_agent` and
  `-p hodor-worker --test worker`, which need Docker.
