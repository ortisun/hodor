---
title: The administration interface, operation by operation
description: The OpenAPI document of the administration interface, as the server serves it.
---

# The administration interface, operation by operation

This page shows the OpenAPI document of [the administration interface](admin-api.md): every route, its permission, what it takes and what it answers. The document is the one the server serves at `GET /t/{slug}/api/v1/admin/openapi.json`, without authentication, and the one kept in the repository at [`crates/protocol-http/openapi/admin-v1.json`](https://github.com/ortisun/hodor/blob/develop/crates/protocol-http/openapi/admin-v1.json). A test checks that it and the server's routes say the same thing.

[Download the document](admin-v1.json){ .md-button }

The page does not send requests. To call the interface, start the [development stack](../operations/quick-start.md), get a token, and follow [the example](../examples/administration-interface.md).

<swagger-ui src="admin-v1.json"/>
