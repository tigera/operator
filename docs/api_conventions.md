# API Conventions

Concrete Go and kubebuilder coding conventions for CRD types under `api/v1/`.
This is the *how*; it implements the design rules in
[`principles.md`](principles.md) (the *why* — "API Design", "Respect User
Input", "Resource Ownership") and pairs with the workflow in
[`dev_guidelines.md`](dev_guidelines.md) ("API code", "Code generation").

When adding or changing a CRD field, follow these and finish with the
[checklist](#checklist-for-a-new-field). APIs follow the
[Kubernetes API conventions](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md);
when in doubt, mirror the upstream Kubernetes type you're configuring, and match
a recent similar `*_types.go` file (e.g. `whisker_types.go`,
`whisker_deployment_types.go`).

## Optional vs. required fields

Optional fields — the overwhelming default — are a pointer + `omitempty` + an
`// +optional` marker, with a doc comment:

```go
// Notifications enables calls to an external API for banner text in the Whisker UI.
// +optional
Notifications *NotificationMode `json:"notifications,omitempty"`
```

Use a pointer whenever "unset" must be distinguishable from the zero value
(almost always for optional scalars/bools/ints). Required fields omit the
pointer and `omitempty` and carry `// +required`.

## On/off toggles

Use a named string type with `Enabled`/`Disabled` constants and an Enum marker —
**not** a `*bool`. This is the established repo idiom:

```go
type NotificationMode string

const (
    Disabled NotificationMode = "Disabled"
    Enabled  NotificationMode = "Enabled"
)
// +kubebuilder:validation:Enum=Enabled;Disabled
```

## Validation and defaulting markers

Prefer kubebuilder markers and CEL over reconcile-loop logic (see
[`principles.md`](principles.md)). 

- Any closed set of string values gets `// +kubebuilder:validation:Enum=A;B;C`.
- Numeric fields get `// +kubebuilder:validation:Minimum=`/`Maximum=`.
- **CEL `XValidation`**: any field referenced in a CEL rule **must** have a
  `MaxLength` (strings) or `MaxItems` (lists) bound, or the apiserver rejects the
  CRD. Use `size(self.field) == 0` rather than `self.field == ''` — goimports
  corrupts single quotes in CEL expressions.

## Top-level Kind types

Carry the standard marker block, embed `TypeMeta`/`ObjectMeta`, and add a
`<Kind>List` type plus `SchemeBuilder.Register` in `init()`:

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

Singleton CRDs pin the name to `default` via an `XValidation` rule
(`self.metadata.name == 'default'`). Status uses `[]metav1.Condition`
(Ready/Progressing/Degraded); status messages are user-facing and actionable —
never internal errors or stack traces.

Every file starts with the `Copyright (c) <years> Tigera, Inc.` Apache-2.0
header — copy it from a neighbouring file.

## Reuse shared types

Don't redefine: `Metadata` (`common_types.go`), `ProbeOverride`
(`probe_types.go`), and `corev1`/`appsv1` types (`Affinity`, `Toleration`,
`ResourceRequirements`, `TopologySpreadConstraint`, `RollingUpdateDeployment`).

## Deployment / container override pattern

Every container's resources, scheduling, tolerations, topology, and probe timing
must be overridable (see [`principles.md`](principles.md), "Every container needs
overrides"). When a component runs a Deployment/DaemonSet that needs to be
customizable, follow the established nesting (see `whisker_deployment_types.go`):
`<Comp>Deployment` → `Metadata` + `Spec` (`<Comp>DeploymentSpec`) → `Template`
(`...PodTemplateSpec`) → `Metadata` + `Spec` (`...PodSpec`) →
`Containers []<Comp>DeploymentContainer`. The container type pins `Name` with an
Enum and exposes `Resources` and `ReadinessProbe`/`LivenessProbe` (as
`*ProbeOverride`). Mirror upstream Kubernetes field names and semantics.

## After every API change

See [`dev_guidelines.md`](dev_guidelines.md) for detail. In short:

1. `make gen-files` — regenerates CRD manifests, `zz_generated.deepcopy.go`, and
   client sets. Never hand-edit generated files.
2. Verify cluster-scoped resources weren't flipped to `Namespaced`.
3. If the new config is settable during a manifest-based Calico OSS → operator
   migration, update [`pkg/controller/migration/convert`](https://github.com/tigera/operator/tree/master/pkg/controller/migration/convert).
4. Add cross-field/code-level checks to `pkg/common/validation/` if needed.
5. `make ut UT_DIR=./api/...` (and relevant render/controller packages), then
   `make dirty-check` to confirm generated output is committed.

## Checklist for a new field

- [ ] Genuinely needed (auto-detection isn't enough)?
- [ ] `*T` + `omitempty` + `// +optional` + doc comment (or `// +required`)?
- [ ] Enum/Minimum/Maximum/Pattern markers where the value is constrained?
- [ ] If used in a CEL rule: `MaxLength`/`MaxItems` bound set, no single quotes?
- [ ] On/off toggle modeled as an `Enabled`/`Disabled` enum, not `*bool`?
- [ ] Reuses shared types rather than redefining them?
- [ ] Backward-compatible (additive; doesn't change an existing field's meaning)?
- [ ] `make gen-files` run, scope unchanged, `make dirty-check` clean?
- [ ] `convert` package updated if migration-relevant?
