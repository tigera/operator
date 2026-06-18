---
applyTo: "api/v1/**"
---

# Operator API design (api/v1)

When changing or reviewing CRD types under `api/v1/` (the `*_types.go` files),
follow the operator's API design standards in
[`docs/api_design.md`](../../docs/api_design.md) — the authoritative source.
Flag changes that violate these:

- Optional fields are a pointer + `omitempty` + `// +optional` + a doc comment;
  required fields omit the pointer/`omitempty` and use `// +required`.
- On/off toggles use an `Enabled`/`Disabled` enum (a named string type), not a
  `*bool`.
- Constrained values carry markers: `+kubebuilder:validation:Enum` /
  `Minimum` / `Maximum` / `Pattern`.
- Fields used in a CEL `XValidation` rule must set `MaxLength` / `MaxItems`;
  use `size(self.field) == 0`, never `self.field == ''` (single quotes break
  goimports).
- Prefer kubebuilder markers/CEL over reconcile-loop logic for
  defaulting/validation.
- Reuse shared types (`Metadata`, `ProbeOverride`, `corev1`/`appsv1`) instead of
  redefining them.
- Changes should be additive and backward-compatible — don't change the meaning
  of an existing field or tighten validation on one.
- Every file carries the Tigera Apache-2.0 copyright header.

See `docs/api_design.md` for the full conventions, the Deployment override
pattern, and the per-field checklist.
