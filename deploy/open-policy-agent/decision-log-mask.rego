# Erases the whole input of every decision before Open Policy Agent uploads
# it to Hodor. Hodor records every decision it asks for itself, with the
# tenant's masks applied, so the input of an uploaded decision is never
# needed, and erasing it at the source keeps it off the wire.
#
# Start every instance with this file next to its configuration, for
# example `opa run --server --config-file config.yaml decision-log-mask.rego`.
# It sits outside every tenant's tree, so no bundle can replace it.
# See docs/architecture/contexts/authorization.md, "Who writes it".
package system.log

mask contains "/input"
