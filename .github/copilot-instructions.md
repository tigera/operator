# Copilot instructions: tigera/operator

Kubernetes operator (operator-sdk / controller-runtime) that manages the
lifecycle of Calico and Calico Enterprise installations. Each component has its
own CRD (`api/v1`), controller (`pkg/controller/<component>`), and rendering code
(`pkg/render`).

Read the relevant doc before working in — or reviewing changes to — these areas:

- **API design / changing CRD types in `api/v1`:** [`docs/api_design.md`](../docs/api_design.md)
- **Architecture & design rationale:** [`docs/principles.md`](../docs/principles.md)
- **Developer workflow, code generation, cherry-picks:** [`docs/dev_guidelines.md`](../docs/dev_guidelines.md)
- **Running, testing, debugging:** [`docs/common_tasks.md`](../docs/common_tasks.md)

After changing API/CRD types, run `make gen-files` then `make dirty-check`; never
edit generated files (`zz_generated.deepcopy.go`, `pkg/imports/crds/`,
`pkg/components/`) by hand.
