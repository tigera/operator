# Development Principles

Code architecture and design principles for the tigera/operator repository. For developer workflow, tooling, and day-to-day procedures, see [dev_guidelines.md](dev_guidelines.md).

## API Design

- **APIs are declarative.** The final state of the system should depend only on the current desired state, not on the order of transitions that got there. Going A -> B -> C should leave you in the same state as B -> A -> C, or C -> B -> C.
- **Minimal API surface.** Prefer auto-detection over configuration. Every new field is a maintenance burden and a potential source of user confusion — only add fields when there's a clear, concrete need.
- **Prefer `projectcalico.org/v3` over `crd.projectcalico.org/v1`.** The v3 API group is the standard going forward.
- **Every container needs overrides.** Resource requirements/requests, scheduling, topology, and similar configuration must be overridable for every container. Use the overrides mechanism, and model the API after the upstream Kubernetes API being configured.
- **Prefer kubebuilder defaulting and validation.** Use kubebuilder markers and CEL expressions for defaulting and validation wherever possible. Fall back to reconcile-loop defaulting and validation only when kubebuilder can't express the logic (e.g., cross-resource validation, dynamic defaults based on cluster state).
- **CEL validation rules require bounds.** Always set `MaxLength` / `MaxItems` on fields used in CEL `XValidation` expressions. Use `size(self.field) == 0` instead of `self.field == ''` (goimports corrupts single quotes in CEL).

## Respect User Input

- **Never overwrite user-specified fields.** If a user sets a value on a resource, the operator must not silently replace it with a default or computed value.
- **Never delete user-created resources.** Secrets, ConfigMaps, and other resources created by the user are theirs. The operator should not remove them.
- **Error on inconsistent input, don't guess.** If a user provides configuration that is contradictory or ambiguous, surface a clear error rather than assuming intent. Guessing leads to subtle, hard-to-debug behavior.
- **Track field ownership on shared resources.** Where possible, write fields to APIs like FelixConfiguration, BGPConfiguration, etc. Use an annotation to track which fields the operator originally set. Never update or remove a field that wasn't set by the operator — that would overwrite user intent. If fields on these objects conflict with `operator.tigera.io` API configuration, surface an error.
- **Copy user-provided resources downstream, never modify them.** Users provide input (custom certs, ConfigMaps, pull secrets, etc.) in the `tigera-operator` namespace. The operator copies and reconciles those objects into the downstream namespaces that need them, but must never edit, update, or delete the originals.

## Component Isolation

- **New components default to `calico-system`.** Historically, each component got its own namespace for RBAC, NetworkPolicy, and resource cleanup isolation. In practice this increases cluster footprint significantly. Modern practice is to place new components in `calico-system` and only use a separate namespace when circumstances specifically call for it (e.g., strict multi-tenant isolation requirements).
- **One CRD per component.** Each component has its own CRD, controller, and status manager. Controllers interact through the Kubernetes API, not by calling each other directly.

## Controller Design

- **Watch, reconcile, render, apply.** Controllers follow a consistent pattern:
  1. Watch the primary CRD and dependent resources.
  2. Read current state from the Kubernetes API.
  3. Call into `pkg/render` to generate desired resources.
  4. Apply via `CreateOrUpdateOrDelete`.
  5. Report status via the TigeraStatus API.
- **Render packages are pure.** The `pkg/render` package generates Kubernetes manifests from inputs. It should not make API calls or have side effects — that's the controller's job.
- **Status messages are for users, not developers.** TigeraStatus conditions should be actionable and user-facing. Don't surface internal error strings or stack traces.

## Security

- **Component-to-component communication must be authenticated and encrypted.** Use mTLS or TLS + token-based authentication for all internal communication between operator-managed components.

## Certificates and Secrets

- **Operator-managed secrets use OwnerReferences.** Secrets created by the operator should have OwnerReferences so they get cleaned up automatically.
- **User-provided secrets must NOT have OwnerReferences.** This is how the operator distinguishes user-provided from operator-managed secrets. They may be copied to other namespaces (with OwnerReferences on the copies), but the originals must not be claimed.