# Gateway UI Access (CIG)

Operator-automated exposure of Manager (Enterprise) and Whisker (OSS) UIs
through Calico Ingress Gateway using the Gateway API.

Ticket: PMREQ-821

## Overview

When `spec.gateway` is set on the Manager (or Whisker) CR, the operator
renders Gateway API resources to expose the UI through an Envoy-based
ingress gateway. The user provides only a hostname; the operator handles
TLS certificates, routing, and backend TLS termination automatically.

```yaml
apiVersion: operator.tigera.io/v1
kind: Manager
metadata:
  name: tigera-secure
spec:
  gateway:
    hostname: manager.example.com
```

### Prerequisites

- A `GatewayAPI` CR must exist (name `tigera-secure` or `default`).
  Without it the controller sets a warning on TigeraStatus but does not
  degrade.
- The GatewayAPI controller provisions the Envoy Gateway infrastructure
  (GatewayClass, EnvoyProxy, namespace).

## API

`GatewaySpec` is a shared type in `api/v1/gateway_types.go`, reusable by
both Manager and Whisker CRs.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | `string` | Yes | Gateway listener hostname. Must match `Authentication.spec.managerDomain` when OIDC is configured. |
| `gatewayNamespace` | `*string` | No | Namespace for Gateway and Envoy pods. Default: `calico-system`. |
| `gatewayClassName` | `*string` | No | GatewayClass to use. Auto-resolved if exactly one class exists in the GatewayAPI CR. |

The listener port is hardcoded to 443 (HTTPS).

## Rendered resources

When `spec.gateway` is set, the gateway render component
(`pkg/render/gateway/component.go`) produces:

| Resource | Namespace | Name pattern |
|----------|-----------|--------------|
| `Secret` (TLS) | gateway namespace | from `KeyPairInterface` |
| `Gateway` | gateway namespace | `{prefix}-gateway` |
| `HTTPRoute` | gateway namespace | `{prefix}-route` |
| `Backend` (EG) | backend namespace | `{prefix}-backend` |
| `ReferenceGrant` | backend namespace | `{prefix}-allow-gateway` (only when gateway and backend namespaces differ) |

For Manager: prefix is `calico-manager`, backend is `tigera-manager:9443`
in `tigera-manager` namespace.

### Resource details

- **Gateway**: HTTPS listener on port 443 with TLS termination. Certificate
  from the operator-managed TLS secret.
- **HTTPRoute**: Routes all traffic from the Gateway to the EG Backend.
  Uses `gateway.envoyproxy.io` group + `Backend` kind (not a plain Service
  ref) to enable backend TLS.
- **Backend** (`gateway.envoyproxy.io/v1alpha1`): Points to the service
  FQDN with TLS settings (CA bundle from `tigera-ca-bundle` ConfigMap,
  SNI set to the service FQDN). Chosen over `BackendTLSPolicy` for
  OpenShift 4.19+ compatibility.
- **ReferenceGrant**: Created only when gateway and backend namespaces
  differ, allowing the HTTPRoute to reference the Backend cross-namespace.

### Cleanup

When `spec.gateway` is removed, the controller passes the gateway
component's objects as `objsToDelete`, removing all rendered resources.

## Controller wiring

In `pkg/controller/manager/manager_controller.go`:

1. The `Reconcile` loop calls `resolveGateway()` after building the main
   manager config but before rendering components.
2. `resolveGateway()`:
   - Fetches the `GatewayAPI` CR. If missing, sets a warning and returns
     nil (no gateway component, no degraded status).
   - Resolves the `GatewayClassName`: if not specified in the CR, uses the
     single class from GatewayAPI; if multiple exist, returns an error.
     If zero classes, defaults to `tigera-gateway-class`.
   - Checks OIDC hostname consistency (Manager only): if an Authentication
     CR exists with a `managerDomain`, it must match `spec.gateway.hostname`.
   - Provisions a TLS keypair via `certificatemanagement`.
   - Returns a `gateway.Component` with the resolved configuration.
3. The gateway component is appended to the component list and processed
   by `CreateOrUpdateOrDelete`.

## RBAC

The operator ClusterRole requires:

```yaml
# Gateway API core resources
- apiGroups: ["gateway.networking.k8s.io"]
  resources: ["gateways", "httproutes", "referencegrants"]
  verbs: ["create", "delete", "get", "list", "patch", "update", "watch"]

# Envoy Gateway Backend
- apiGroups: ["gateway.envoyproxy.io"]
  resources: ["backends"]
  verbs: ["create", "delete", "get", "list", "patch", "update", "watch"]
```

These rules are defined in the calico-private Helm chart
(`charts/tigera-operator/templates/tigera-operator/02-role-tigera-operator.yaml`).

## Future work

- **Whisker**: Add `spec.gateway` to `WhiskerSpec` using the same
  `GatewaySpec` type and `pkg/render/gateway` component.
- **Whisker HTTPS**: Make Whisker backend serve HTTPS (currently HTTP-only)
  before enabling gateway access.
