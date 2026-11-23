---
title: The Authorization API, operation by operation
description: The OpenAPI document of the Authorization API, as the server serves it.
---

# The Authorization API, operation by operation

This page shows the OpenAPI document of [the Authorization API](api-spec.md#authorization-api): every route, its scope, what it takes and what it answers. The document is the one the server serves at `GET /t/{slug}/api/v1/authorization/openapi.json`, without authentication, and the one kept in the repository at [`crates/protocol-http/openapi/authorization-v1.json`](https://github.com/ortisun/hodor/blob/develop/crates/protocol-http/openapi/authorization-v1.json). A test checks that it and the server's routes say the same thing.

[Download the document](authorization-v1.json){ .md-button }

The page does not send requests.

<swagger-ui src="authorization-v1.json"/>
