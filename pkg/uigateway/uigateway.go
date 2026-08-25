// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package uigateway carries the controller-side logic shared by the UI
// components (Manager, Whisker) that expose themselves through Calico
// Ingress Gateway: label-driven cleanup, gateway health read-back, namespace
// provisioning, class resolution, and watch setup. The rendering lives in
// pkg/render/gateway; this package holds what a reconciler needs around it.
package uigateway

import (
	"context"
	stderrors "errors"
	"fmt"
	"slices"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	gapi "sigs.k8s.io/gateway-api/apis/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/gatewayapi"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	rgateway "github.com/tigera/operator/pkg/render/gateway"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// Config identifies one UI component's gateway resources; data only — the
// client lives on Helper.
type Config struct {
	// ResourcePrefix names the component's gateway resources and is the
	// value of the operator.tigera.io/gateway label on its Gateway.
	ResourcePrefix string

	// TLSSecretName is the gateway listener certificate secret.
	TLSSecretName string

	// BackendNamespace holds the Backend and ReferenceGrant.
	BackendNamespace string

	BackendServiceName string
	BackendPort        int32

	// BackendCABundleConfigMapName is the bundle the gateway trusts when it
	// re-originates TLS to the backend.
	BackendCABundleConfigMapName string

	// RouteRequestTimeout overrides Envoy Gateway's default route timeout. Set
	// it for a component that streams, where the default would cut the stream.
	RouteRequestTimeout *string

	// ExtraProxyObjects are the variant's additions beside the proxy in the
	// backend namespace, or nil; see pkg/enterprise/uigateway.
	ExtraProxyObjects []client.Object

	OpenShift bool
}

// Helper renders and cleans up one UI component's gateway resources.
type Helper struct {
	cli client.Client
	cfg Config
}

// NewHelper returns the helper for one UI component's gateway.
func NewHelper(cli client.Client, cfg Config) *Helper {
	return &Helper{cli: cli, cfg: cfg}
}

// Components renders the component's gateway resources, plus deletion
// components for any namespace the Gateway has left behind. An *Error is a
// condition the caller reports on its own status; any other error is a
// cluster failure to return for backoff.
func (h *Helper) Components(
	ctx context.Context,
	spec *operatorv1.IngressGatewaySpec,
	keyPair certificatemanagement.KeyPairInterface,
) ([]render.Component, error) {
	// Under certificateManagement, keys are minted in-pod as files, but Envoy
	// Gateway reads the listener key from a Secret, so there is nothing to serve.
	if keyPair != nil && keyPair.UseCertificateManagement() {
		return nil, &Error{Reason: operatorv1.InvalidConfigurationError,
			Msg: "spec.ingressGateway is not supported when certificateManagement is enabled"}
	}

	gatewayAPI, msg, err := gatewayapi.GetGatewayAPI(ctx, h.cli)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, &Error{Reason: operatorv1.ResourceNotFound,
				Msg: "GatewayAPI CR not found; GatewayAPI is a prerequisite for spec.ingressGateway", Err: err}
		}
		// A read failure may be transient, so it goes back as a plain error
		// for backoff rather than a condition that waits on a watch.
		return nil, fmt.Errorf("%s: %w", msg, err)
	}

	className, err := h.resolveClassName(spec, gatewayAPI)
	if err != nil {
		return nil, &Error{Reason: operatorv1.InvalidConfigurationError, Msg: "Failed to resolve gateway class", Err: err}
	}

	// The backend namespace already exists and belongs to another controller,
	// so only a namespace the user named is created here.
	gwNS := spec.NamespaceOrDefault()
	if gwNS != h.cfg.BackendNamespace {
		if err := h.ensureNamespace(ctx, gwNS); err != nil {
			return nil, fmt.Errorf("failed to ensure gateway namespace %s: %w", gwNS, err)
		}
	}

	// Stale-namespace cleanup lands in the same reconcile as the new render.
	components, err := h.StaleComponents(ctx, gwNS)
	if err != nil {
		return nil, err
	}

	return append(components, rgateway.Component(&rgateway.Configuration{
		Hostname:                     spec.Hostname,
		GatewayNamespace:             gwNS,
		GatewayClassName:             className,
		BackendServiceName:           h.cfg.BackendServiceName,
		BackendPort:                  h.cfg.BackendPort,
		BackendNamespace:             h.cfg.BackendNamespace,
		BackendCABundleConfigMapName: h.cfg.BackendCABundleConfigMapName,
		TLSKeyPair:                   keyPair,
		ResourcePrefix:               h.cfg.ResourcePrefix,
		ExtraProxyObjects:            h.cfg.ExtraProxyObjects,
		OpenShift:                    h.cfg.OpenShift,
		RouteRequestTimeout:          h.cfg.RouteRequestTimeout,
	})), nil
}

// Namespaces returns the sorted, de-duplicated namespaces of Gateways carrying
// this component's gateway label. A cluster that does not serve the Gateway kind
// has none, so it returns empty rather than an error.
func (h *Helper) Namespaces(ctx context.Context) ([]string, error) {
	gwList := &gapi.GatewayList{}
	if err := h.cli.List(ctx, gwList, client.MatchingLabels{rgateway.GatewayLabel: h.cfg.ResourcePrefix}); err != nil {
		var noMatch *apimeta.NoKindMatchError
		if stderrors.As(err, &noMatch) {
			return nil, nil
		}
		return nil, err
	}
	var namespaces []string
	for _, gw := range gwList.Items {
		if !slices.Contains(namespaces, gw.Namespace) {
			namespaces = append(namespaces, gw.Namespace)
		}
	}
	slices.Sort(namespaces)
	return namespaces, nil
}

// StaleComponents returns deletion components for every labeled Gateway
// outside the desired namespace — leftovers of a gatewayNamespace change.
func (h *Helper) StaleComponents(ctx context.Context, desiredNS string) ([]render.Component, error) {
	strays, err := h.Namespaces(ctx)
	if err != nil {
		return nil, err
	}
	var components []render.Component
	for _, ns := range strays {
		if ns == desiredNS {
			continue
		}
		owned, err := h.ownsNamespace(ctx, ns)
		if err != nil {
			return nil, err
		}
		components = append(components, rgateway.DeletionComponent(&rgateway.DeletionConfiguration{
			ResourcePrefix:    h.cfg.ResourcePrefix,
			StaleNamespace:    ns,
			BackendNamespace:  h.cfg.BackendNamespace,
			TLSSecretName:     h.cfg.TLSSecretName,
			ExtraProxyObjects: h.cfg.ExtraProxyObjects,
			DeleteNamespace:   owned,
			TargetNamespace:   desiredNS,
		}))
	}
	return components, nil
}

// Teardown returns deletion components for every labeled Gateway namespace,
// plus the backend namespace, which holds the Backend and ReferenceGrant.
// No labeled Gateway means nothing to do: the Gateway is rendered first, so
// nothing else can exist without one.
func (h *Helper) Teardown(ctx context.Context) ([]render.Component, error) {
	namespaces, err := h.Namespaces(ctx)
	if err != nil {
		return nil, err
	}
	if len(namespaces) == 0 {
		return nil, nil
	}
	if !slices.Contains(namespaces, h.cfg.BackendNamespace) {
		namespaces = append(namespaces, h.cfg.BackendNamespace)
	}
	var components []render.Component
	for _, ns := range namespaces {
		owned, err := h.ownsNamespace(ctx, ns)
		if err != nil {
			return nil, err
		}
		components = append(components, rgateway.DeletionComponent(&rgateway.DeletionConfiguration{
			ResourcePrefix:    h.cfg.ResourcePrefix,
			StaleNamespace:    ns,
			BackendNamespace:  h.cfg.BackendNamespace,
			TLSSecretName:     h.cfg.TLSSecretName,
			ExtraProxyObjects: h.cfg.ExtraProxyObjects,
			DeleteNamespace:   owned,
		}))
	}
	return components, nil
}

// UnhealthyReason returns why the Gateway or HTTPRoute is not ready, or ""
// when both are healthy. The caller degrades and requeues; nothing is torn
// down. NotFound counts too: the cache may not yet hold what this reconcile
// just applied, and the requeue re-checks.
func (h *Helper) UnhealthyReason(ctx context.Context, gatewayNS string) string {
	gatewayName := h.cfg.ResourcePrefix + "-gateway"
	routeName := h.cfg.ResourcePrefix + "-route"

	gw := &gapi.Gateway{}
	if err := h.cli.Get(ctx, client.ObjectKey{Name: gatewayName, Namespace: gatewayNS}, gw); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Sprintf("Gateway %s/%s not found yet", gatewayNS, gatewayName)
		}
		return fmt.Sprintf("Failed to read Gateway %s/%s status: %v", gatewayNS, gatewayName, err)
	}

	if msg := unhealthyCondition(gw.Status.Conditions, string(gapi.GatewayConditionAccepted), "Gateway not accepted"); msg != "" {
		return msg
	}
	if msg := unhealthyCondition(gw.Status.Conditions, string(gapi.GatewayConditionProgrammed), "Gateway not programmed"); msg != "" {
		return msg
	}

	route := &gapi.HTTPRoute{}
	if err := h.cli.Get(ctx, client.ObjectKey{Name: routeName, Namespace: gatewayNS}, route); err != nil {
		if errors.IsNotFound(err) {
			return fmt.Sprintf("HTTPRoute %s/%s not found yet", gatewayNS, routeName)
		}
		return fmt.Sprintf("Failed to read HTTPRoute %s/%s status: %v", gatewayNS, routeName, err)
	}
	for _, ps := range route.Status.Parents {
		if msg := unhealthyCondition(ps.Conditions, string(gapi.RouteConditionAccepted), "HTTPRoute not accepted"); msg != "" {
			return msg
		}
		if msg := unhealthyCondition(ps.Conditions, string(gapi.RouteConditionResolvedRefs), "HTTPRoute refs not resolved"); msg != "" {
			return msg
		}
	}

	return ""
}

// unhealthyCondition returns a message when the named condition exists and is
// not True. A missing condition is healthy: the controller has not written
// its verdict yet, and Accepted/Programmed gate readiness once it does.
func unhealthyCondition(conditions []metav1.Condition, condType, msgPrefix string) string {
	for _, cond := range conditions {
		if cond.Type == condType && cond.Status != metav1.ConditionTrue {
			return fmt.Sprintf("%s: %s", msgPrefix, cond.Message)
		}
	}
	return ""
}

// ownsNamespace reports whether the operator created this namespace for the
// component's gateway, which is the only case where teardown may delete it.
func (h *Helper) ownsNamespace(ctx context.Context, name string) (bool, error) {
	if name == h.cfg.BackendNamespace {
		return false, nil
	}
	ns := &corev1.Namespace{}
	if err := h.cli.Get(ctx, types.NamespacedName{Name: name}, ns); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return ns.Labels[rgateway.GatewayLabel] == h.cfg.ResourcePrefix, nil
}

// EnsureNamespace creates the gateway namespace if it does not exist.
// The namespace is created without an owner reference and is never deleted by
// the operator: a user-provided namespace may hold other workloads.
func (h *Helper) ensureNamespace(ctx context.Context, name string) error {
	err := h.cli.Get(ctx, types.NamespacedName{Name: name}, &corev1.Namespace{})
	if err == nil || !errors.IsNotFound(err) {
		return err
	}
	// The gateway label marks the namespace as ours, so teardown can tell a
	// namespace the operator created from one the user already had.
	ns := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"name":                name,
				rgateway.GatewayLabel: h.cfg.ResourcePrefix,
			},
		},
	}
	if err := h.cli.Create(ctx, ns); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// ResolveClassName determines the GatewayClass name to use based on the
// user's spec.ingressGateway.gatewayClassName or the GatewayAPI CR's
// configured classes.
func (h *Helper) resolveClassName(gw *operatorv1.IngressGatewaySpec, gatewayAPI *operatorv1.GatewayAPI) (string, error) {
	if gw.GatewayClassName != nil && *gw.GatewayClassName != "" {
		name := *gw.GatewayClassName
		for _, c := range gatewayAPI.Spec.GatewayClasses {
			if c.Name == name {
				return name, nil
			}
		}
		return "", fmt.Errorf("GatewayClass %q not found; verify GatewayAPI CR includes this class", name)
	}

	classes := gatewayAPI.Spec.GatewayClasses
	switch len(classes) {
	case 0:
		return "", fmt.Errorf("no GatewayClasses configured on GatewayAPI CR")
	case 1:
		return classes[0].Name, nil
	default:
		return "", fmt.Errorf("multiple GatewayClasses configured on GatewayAPI CR; set spec.ingressGateway.gatewayClassName to select one")
	}
}

// AddWatches registers the watches a UI gateway reconciler depends on. Gateway
// health lives in status, which does not bump the generation, so matching by
// name and accepting every event is what keeps the default generation-based
// predicate from dropping these.
func AddWatches(c ctrlruntime.Controller, k8sClientset kubernetes.Interface, log logr.Logger, resourcePrefix, tlsSecretName string) error {
	if err := utils.AddSecretsWatch(c, tlsSecretName, ""); err != nil {
		return fmt.Errorf("failed to watch the secret '%s': %w", tlsSecretName, err)
	}

	gatewayWatchPredicate := predicate.NewPredicateFuncs(func(o client.Object) bool {
		return o.GetName() == resourcePrefix+"-gateway" ||
			o.GetName() == resourcePrefix+"-route"
	})
	go utils.WaitToAddResourceWatch(c, k8sClientset, log, nil, []client.Object{
		&gapi.Gateway{
			TypeMeta:   metav1.TypeMeta{Kind: "Gateway", APIVersion: "gateway.networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: resourcePrefix + "-gateway"},
		},
		&gapi.HTTPRoute{
			TypeMeta:   metav1.TypeMeta{Kind: "HTTPRoute", APIVersion: "gateway.networking.k8s.io/v1"},
			ObjectMeta: metav1.ObjectMeta{Name: resourcePrefix + "-route"},
		},
	}, gatewayWatchPredicate)
	return nil
}

// Error is a gateway condition the caller reports on its own status rather
// than returning: the reason and wording live here so both UI controllers
// report it identically. Detect it with errors.As; anything else is a cluster
// failure the caller returns for backoff.
type Error struct {
	Reason operatorv1.TigeraStatusReason
	Msg    string
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Msg + ": " + e.Err.Error()
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.Err }
