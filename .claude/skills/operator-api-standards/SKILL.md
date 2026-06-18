---
name: operator-api-standards
description: Standards, conventions, and dos/don'ts for adding or changing CRD types in the tigera/operator API (api/v1). Use this skill whenever editing or creating files under api/v1/ (any *_types.go), adding/removing/renaming a CRD field, introducing a new Kind/CRD, adding kubebuilder validation or defaulting markers, or designing an overrides/configuration field. Trigger even if the user doesn't mention "standards" — any change to operator CRD types should follow these conventions.
---

# Operator API Standards

Guidance for changing CRD types under `api/v1/`. The authoritative design rationale lives in
[`docs/principles.md`](../../../docs/principles.md) ("API Design", "Respect User Input", "Resource
Ownership") and [`docs/dev_guidelines.md`](../../../docs/dev_guidelines.md) ("API code"). This skill
distills those into concrete, checkable rules and the repo's coding conventions. Read those docs when
you need the "why"; follow this skill for the "how".

Every operator API is **declarative**: the same desired state must always converge to the same result,
regardless of the path taken to get there.

## Before you start

- APIs follow the [Kubernetes API conventions](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md). When in doubt, mirror the upstream Kubernetes type you're configuring.
- Look at a recent, similar `*_types.go` file (e.g. `whisker_types.go`, `whisker_deployment_types.go`) and match its structure exactly.

## Core design rules (the dos)

- **Minimal API surface.** Prefer auto-detection over configuration. Every field is a permanent
  maintenance burden and a support/upgrade liability. Only add a field when there's a concrete,
  demonstrated need — not "someone might want this".
- **Prefer kubebuilder markers over reconcile-loop logic** for defaulting and validation. Fall back to
  code in the controller only when kubebuilder/CEL can't express it (cross-resource checks, defaults
  that depend on cluster state).
- **Every container needs overrides.** Resource requests/limits, scheduling, tolerations, topology,
  probe timing, etc. must be overridable for every container the component runs. Model the override
  type after the upstream Kubernetes API (see the Deployment override pattern below).
- **Prefer `projectcalico.org/v3`** over `crd.projectcalico.org/v1` when referencing Calico APIs.
- **Make changes additive and backward-compatible.** Fields are effectively forever. Adding an optional
  field is safe; changing the type/meaning of an existing field, tightening validation, or removing a
  field breaks existing CRs on upgrade.

## Respect user input (the don'ts)

- **Never overwrite a user-specified field** with a default or computed value.
- **Never delete or modify user-created resources** (Secrets, ConfigMaps, certs, pull secrets). The
  operator may *copy* them into downstream namespaces, but the originals are off-limits.
- **Error on contradictory input — don't guess.** Ambiguous/conflicting config should surface a clear,
  user-facing error, not a silent assumption.
- **Don't claim user-provided resources with OwnerReferences.** Absence of an OwnerReference is how the
  operator tells user-provided from operator-managed objects.

## Go / kubebuilder coding conventions

Match these exactly — `make gen-files` and CI depend on them.

**Optional fields:** pointer + `omitempty` + `// +optional` marker, and a doc comment. The overwhelming
default in this repo is optional (688 `+optional` vs 27 `+required`).
```go
// Notifications enables calls to an external API for banner text in the Whisker UI.
// +optional
Notifications *NotificationMode `json:"notifications,omitempty"`
```
Use a pointer whenever "unset" must be distinguishable from the zero value (almost always for optional
scalars/bools/ints). Required fields omit the pointer and `omitempty` and carry `// +required`.

**Enabled/Disabled pattern:** for on/off toggles, use a named string type with `Enabled`/`Disabled`
constants and a kubebuilder Enum — not a `*bool`. This is the established repo idiom
(`+kubebuilder:validation:Enum=Enabled;Disabled` appears 14×).
```go
type NotificationMode string
const (
    Disabled NotificationMode = "Disabled"
    Enabled  NotificationMode = "Enabled"
)
// +kubebuilder:validation:Enum=Enabled;Disabled
```

**Enums:** any closed set of string values gets `// +kubebuilder:validation:Enum=A;B;C`.

**Numeric bounds:** add `+kubebuilder:validation:Minimum=`/`Maximum=` to int fields.

**CEL validation (`XValidation`):** any field referenced in a CEL rule **must** have a `MaxLength`
(strings) or `MaxItems` (lists) bound, or the apiserver rejects the CRD. Use `size(self.field) == 0`
rather than `self.field == ''` — goimports corrupts single quotes in CEL expressions.

**Top-level Kind types** carry the standard marker block and embed TypeMeta/ObjectMeta, plus a
`<Kind>List` type and `SchemeBuilder.Register` in `init()`:
```go
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
type Whisker struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`
    Spec   WhiskerSpec   `json:"spec,omitempty"`
    Status WhiskerStatus `json:"status,omitempty"`
}
```
Singleton CRDs pin the name to `default` via an `XValidation` rule (`self.metadata.name == 'default'`).

**Status** uses `[]metav1.Condition` (Ready/Progressing/Degraded). Status messages are user-facing and
actionable — never surface internal errors or stack traces.

**Copyright header:** every file starts with the `Copyright (c) <years> Tigera, Inc.` Apache-2.0 header.
Copy it from a neighbouring file.

**Reuse shared types** instead of redefining: `Metadata` (`common_types.go`), `ProbeOverride`
(`probe_types.go`), and `corev1`/`appsv1` types (`Affinity`, `Toleration`, `ResourceRequirements`,
`TopologySpreadConstraint`, `RollingUpdateDeployment`).

## Deployment / container override pattern

When a component runs a Deployment (or DaemonSet) that needs to be customizable, follow the established
nested shape (see `whisker_deployment_types.go`): `<Comp>Deployment` → `Metadata` + `Spec`
(`<Comp>DeploymentSpec`) → `Template` (`...PodTemplateSpec`) → `Metadata` + `Spec` (`...PodSpec`) →
`Containers []<Comp>DeploymentContainer`. The container type pins `Name` with an Enum and exposes
`Resources`, `ReadinessProbe`/`LivenessProbe` (as `*ProbeOverride`). Mirror upstream field names and
semantics so users can transfer Kubernetes knowledge directly.

## After every API change (required)

1. `make gen-files` — regenerates CRD manifests (`pkg/imports/crds/`), `zz_generated.deepcopy.go`, and
   client sets. **Never hand-edit generated files.**
2. After gen-files, **verify cluster-scoped resources weren't flipped to `Namespaced`** (a known
   operator-sdk footgun).
3. If the new config can be set during a manifest-based Calico OSS → operator migration, update
   [`pkg/controller/migration/convert`](../../../pkg/controller/migration/convert).
4. Add/extend validation in `pkg/common/validation/` if the field needs cross-field or code-level checks.
5. `make ut UT_DIR=./api/...` (and the relevant render/controller packages), then `make dirty-check`
   to confirm generated output is committed.

## Quick checklist for a new field

- [ ] Genuinely needed (auto-detection isn't enough)?
- [ ] `*T` + `omitempty` + `// +optional` + doc comment (or `// +required` if mandatory)?
- [ ] Enum/Minimum/Maximum/Pattern markers where the value is constrained?
- [ ] If used in a CEL rule: `MaxLength`/`MaxItems` bound set, no single quotes?
- [ ] On/off toggle modeled as an `Enabled`/`Disabled` enum, not `*bool`?
- [ ] Reuses shared types rather than redefining them?
- [ ] Backward-compatible (additive, doesn't change existing field meaning)?
- [ ] `make gen-files` run, scope unchanged, `make dirty-check` clean?
- [ ] `convert` package updated if migration-relevant?
