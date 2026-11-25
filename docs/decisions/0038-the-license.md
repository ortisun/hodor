# Decision 0038: Hodor is licensed under the MIT License

Status: Accepted (requested by the project owner)

## Context

Until 0.3.0 the repository had no license, so nobody but its author could lawfully use, change or share Hodor, whatever the code said about being open. The project owner asked for a permissive license, and chose MIT among these:

| License | What it asks | Where it falls short |
|---|---|---|
| MIT | Keep the copyright notice and the license text in copies | No explicit patent grant |
| Apache-2.0 | Keep the notices, state changes, carry the `NOTICE` file | Asks the most of the three; it is the only one with an explicit patent grant |
| 0BSD, the BSD Zero Clause License | Nothing, not even the notice | No explicit patent grant; less known |

## Decision

- **Hodor is licensed under MIT.** Anyone may use, copy, change, merge, publish, distribute, sublicense and sell it, for any purpose, as long as copies keep the copyright notice and the license text. It is the license most of Hodor's own dependencies use, approved by the Open Source Initiative and named `MIT` in SPDX.
- **The copyright notice names the Hodor authors**, `Copyright (c) 2026 The Hodor authors`, so that it stays true as people contribute.
- **The license covers what this repository holds**: the code, the documentation, the charts, the installation files and the design system. The `LICENSE` file at the root carries its text, every crate says `license = "MIT"` through the workspace, and every `package.json` says `"license": "MIT"`.
- **What Hodor bundles keeps its own license.** The crates and packages it depends on, and the fonts the pages carry, are under the licenses [the supply chain](../security/supply-chain.md#which-licenses-are-allowed) allows. Those that ask for attribution are named in the software bill of materials attached to each image; whoever redistributes the image passes their notices on.
- **Contributions come in under the same license.** Opening a pull request offers the change under MIT.

## Consequences

- Hodor can be embedded in closed products, forked and sold without asking anyone; what it asks is that the notice travels with the code.
- There is no patent grant: someone who contributes code covered by their own patent gives no written promise not to assert it. Apache-2.0 would give that promise at the cost of more conditions.
- Changing to another license later binds only what is released afterwards; what was released under MIT stays available under it.
