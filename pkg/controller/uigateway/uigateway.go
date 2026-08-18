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
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render"
	rgateway "github.com/tigera/operator/pkg/render/gateway"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

// Config identifies one UI component's gateway resources.
type Config struct {
	Client client.Client

	// ResourcePrefix names the component's gateway resources and is the
	// value of the operator.tigera.io/gateway label on its Gateway.
	ResourcePrefix string

	// TLSSecretName is the gateway listener certificate secret.
	TLSSecretName string

	// BackendNamespace holds the Backend and ReferenceGrant.
	BackendNamespace string

	// Enterprise controls whether the proxy SA and RoleBinding are part of
	// the component's rendered set; the proxy NetworkPolicy is rendered on
	// both variants.
	Enterprise bool
}

// Namespaces returns the sorted, de-duplicated namespaces of Gateways carrying
// this component's gateway label. A cluster that does not serve the Gateway kind
// has none, so it returns empty rather than an error.
func (c *Config) Namespaces(ctx context.Context) ([]string, error) {
	gwList := &gapi.GatewayList{}
	if err := c.Client.List(ctx, gwList, client.MatchingLabels{rgateway.GatewayLabel: c.ResourcePrefix}); err != nil {
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

// MoveCleanup returns deletion components for every labeled Gateway outside
// the desired namespace — leftovers of a gatewayNamespace change. The
// Backend is kept and the ReferenceGrant handled per the move target; see
// DeletionConfiguration.MoveTargetNamespace.
func (c *Config) MoveCleanup(ctx context.Context, desiredNS string) ([]render.Component, error) {
	strays, err := c.Namespaces(ctx)
	if err != nil {
		return nil, err
	}
	var components []render.Component
	for _, ns := range strays {
		if ns == desiredNS {
			continue
		}
		components = append(components, rgateway.DeletionComponent(&rgateway.DeletionConfiguration{
			ResourcePrefix:      c.ResourcePrefix,
			StaleNamespace:      ns,
			BackendNamespace:    c.BackendNamespace,
			TLSSecretName:       c.TLSSecretName,
			Enterprise:          c.Enterprise,
			MoveTargetNamespace: desiredNS,
		}))
	}
	return components, nil
}

// Teardown returns deletion components for every labeled Gateway namespace,
// plus the backend namespace, which contains the Backend and ReferenceGrant.
//
// If no labeled Gateway exists, nothing is returned. The Gateway is rendered
// before any other gateway resources, so those resources cannot exist without
// a corresponding Gateway.
func (c *Config) Teardown(ctx context.Context) ([]render.Component, error) {
	namespaces, err := c.Namespaces(ctx)
	if err != nil {
		return nil, err
	}
	if len(namespaces) == 0 {
		return nil, nil
	}
	if !slices.Contains(namespaces, c.BackendNamespace) {
		namespaces = append(namespaces, c.BackendNamespace)
	}
	var components []render.Component
	for _, ns := range namespaces {
		components = append(components, rgateway.DeletionComponent(&rgateway.DeletionConfiguration{
			ResourcePrefix:   c.ResourcePrefix,
			StaleNamespace:   ns,
			BackendNamespace: c.BackendNamespace,
			TLSSecretName:    c.TLSSecretName,
			Enterprise:       c.Enterprise,
		}))
	}
	return components, nil
}

// UnsupportedCertificateManagement reports whether the gateway can be rendered
// at all. Under certificateManagement the operator does not mint key pairs: a
// pod's key is generated in the pod and written as files, which a Gateway
// listener cannot consume — Envoy Gateway reads the key out of a Secret. The
// key pair handed back here is a placeholder with no private key, so rendering
// it would give Envoy a listener certificate it cannot serve.
func UnsupportedCertificateManagement(keyPair certificatemanagement.KeyPairInterface) string {
	if keyPair == nil || !keyPair.UseCertificateManagement() {
		return ""
	}
	return "spec.ingressGateway is not supported when certificateManagement is enabled"
}

// UnhealthyReason reads the Gateway and HTTPRoute status conditions and
// returns why the gateway is not ready, or "" when every condition is
// healthy. An unhealthy gateway degrades the component — the caller sets
// Degraded and requeues; deployed resources are never torn down. NotFound is
// reported too: the requeue re-checks once the cache catches up with the
// resources this reconcile just applied.
func (c *Config) UnhealthyReason(ctx context.Context, gatewayNS string) string {
	gatewayName := c.ResourcePrefix + "-gateway"
	routeName := c.ResourcePrefix + "-route"

	gw := &gapi.Gateway{}
	if err := c.Client.Get(ctx, client.ObjectKey{Name: gatewayName, Namespace: gatewayNS}, gw); err != nil {
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
	if err := c.Client.Get(ctx, client.ObjectKey{Name: routeName, Namespace: gatewayNS}, route); err != nil {
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

// EnsureNamespace creates the gateway namespace if it does not exist.
// The namespace is created without an owner reference and is never deleted by
// the operator: a user-provided namespace may hold other workloads.
func EnsureNamespace(ctx context.Context, c client.Client, name string) error {
	err := c.Get(ctx, types.NamespacedName{Name: name}, &corev1.Namespace{})
	if err == nil || !errors.IsNotFound(err) {
		return err
	}
	ns := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"name": name},
		},
	}
	if err := c.Create(ctx, ns); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// ResolveClassName determines the GatewayClass name to use based on the
// user's spec.ingressGateway.gatewayClassName or the GatewayAPI CR's
// configured classes.
func ResolveClassName(gw *operatorv1.IngressGatewaySpec, gatewayAPI *operatorv1.GatewayAPI) (string, error) {
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

// AddWatches registers the watches a UI gateway reconciler depends on: the
// gateway TLS secret across all namespaces (the truth copy lives in the
// operator namespace, the rendered copy in the user-configurable gateway
// namespace), and the Gateway/HTTPRoute status. Gateway health lives in
// status, which does not bump the generation, so the default generation-based
// predicate would drop these events — match by name and accept every event
// instead. The Gateway/HTTPRoute watch arms once the Gateway API CRDs exist.
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
