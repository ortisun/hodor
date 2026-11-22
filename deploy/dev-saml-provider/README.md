# The development SAML identity provider

**Not for anything real.** `signing-key.pem` is a private key written in the repository: anyone can sign with it. It exists so that the development stack, the browser tests and the demonstration have a SAML identity provider that signs real responses.

- `saml-provider.mjs`: the identity provider, one file for Node.js with no dependencies. It lets anyone sign in as anyone.
- `signing-key.pem`, `certificate.pem`: its RSA key of 2048 bits and a self-signed certificate for it, made with `openssl req -x509 -newkey rsa:2048 -nodes -days 36500`.

How to use it is in [local setup](../../docs/development/local-setup.md#the-development-saml-identity-provider).
