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

package istio

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/tigera/operator/pkg/render/common/securitycontext"
)

const (
	// L7WaypointDefaultsConfigMapName is the class-level defaults ConfigMap that
	// Istio's deployment controller applies to every Gateway using the
	// istio-waypoint GatewayClass.
	L7WaypointDefaultsConfigMapName = "tigera-waypoint-l7-defaults"

	// L7WaypointALSFilterName is the EnvoyFilter that enables gRPC ALS access
	// logging on the waypoint's main_internal listener.
	L7WaypointALSFilterName = "tigera-waypoint-l7-als"

	// L7WaypointSrcPortFilterName is the EnvoyFilter that captures the original
	// client IP from the Forwarded header on the connect_terminate listener and
	// propagates it as filter state to main_internal.
	L7WaypointSrcPortFilterName = "tigera-waypoint-l7-srcport"

	// IstioWaypointGatewayClass is the standard Istio-provided GatewayClass for
	// waypoint proxies. Every Gateway using this class automatically receives
	// L7 logging via the class-level defaults ConfigMap.
	IstioWaypointGatewayClass = "istio-waypoint"

	// gatewayClassDefaultsLabel is the label Istio's deployment controller uses
	// to find class-level defaults ConfigMaps for a given GatewayClass.
	gatewayClassDefaultsLabel = "gateway.istio.io/defaults-for-class"

	// forwardedFilterStateKey is the filter state key used to propagate the
	// original client IP from connect_terminate to main_internal.
	forwardedFilterStateKey = "io.tigera.forwarded_header"

	l7CollectorSocketMountPath = "/var/run/l7-collector"
	l7CollectorSocketURI       = "unix:///var/run/l7-collector/l7-collector.sock"
	felixSyncMountPath         = "/var/run/felix"
	felixDialTarget            = "/var/run/felix/nodeagent/socket"

	socketVolumeName = "l7-collector-socket"
	felixVolumeName  = "felix-sync"
)

// EnvoyFilterGVK returns the GroupVersionKind for Istio EnvoyFilter resources.
func EnvoyFilterGVK() schema.GroupVersionKind {
	return envoyFilterGV.WithKind("EnvoyFilter")
}

// L7WaypointObjects returns the three resources the operator manages to enable
// L7 logging on every Gateway using the istio-waypoint GatewayClass:
//
//   - A defaults ConfigMap (gateway.istio.io/defaults-for-class=istio-waypoint)
//     that Istio applies as a strategic merge patch to every waypoint
//     Deployment, injecting the l7-collector sidecar and its shared volumes.
//   - An EnvoyFilter enabling gRPC ALS on main_internal.
//   - An EnvoyFilter capturing the Forwarded header on connect_terminate and
//     propagating it as filter state to main_internal.
//
// All three are created in the Istio system namespace (the root namespace
// Istiod reads class-level defaults and mesh-wide EnvoyFilters from).
func L7WaypointObjects(namespace, l7CollectorImage string) []client.Object {
	return []client.Object{
		renderL7DefaultsConfigMap(namespace, l7CollectorImage),
		renderALSEnvoyFilter(namespace),
		renderSrcPortEnvoyFilter(namespace),
	}
}

// renderL7DefaultsConfigMap builds the class-level defaults ConfigMap. Istio's
// deployment controller reads the `deployment` key as a strategic merge patch
// onto every waypoint Deployment's PodSpec.
func renderL7DefaultsConfigMap(namespace, image string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      L7WaypointDefaultsConfigMapName,
			Namespace: namespace,
			Labels: map[string]string{
				gatewayClassDefaultsLabel: IstioWaypointGatewayClass,
			},
		},
		Data: map[string]string{
			"deployment": waypointDeploymentOverlay(image),
		},
	}
}

// waypointDeploymentOverlay produces the YAML strategic merge patch that gets
// applied to every waypoint Deployment, injecting the l7-collector sidecar,
// the shared unix socket volume, and the Felix CSI volume. An additional
// volumeMount is applied to the existing istio-proxy container so it can write
// access logs to the shared socket.
func waypointDeploymentOverlay(image string) string {
	sc := securitycontext.NewNonRootContext()
	sc.ReadOnlyRootFilesystem = ptr.To(true)

	sidecar := corev1.Container{
		Name:  "l7-collector",
		Image: image,
		Args:  []string{"--mode=waypoint"},
		Env: []corev1.EnvVar{
			{Name: "FELIX_DIAL_TARGET", Value: felixDialTarget},
			{Name: "LOG_LEVEL", Value: "Info"},
			{Name: "OWNING_GATEWAY_NAME", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "metadata.labels['gateway.networking.k8s.io/gateway-name']",
				},
			}},
			{Name: "OWNING_GATEWAY_NAMESPACE", ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
			}},
		},
		VolumeMounts: []corev1.VolumeMount{
			{Name: socketVolumeName, MountPath: l7CollectorSocketMountPath},
			{Name: felixVolumeName, MountPath: felixSyncMountPath},
		},
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("50m"),
				corev1.ResourceMemory: resource.MustParse("64Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("200m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
		},
		SecurityContext: sc,
	}

	// Only specify the istio-proxy container's new volumeMount; strategic merge
	// on containers is keyed by name, so existing fields are preserved.
	istioProxyPatch := corev1.Container{
		Name: "istio-proxy",
		VolumeMounts: []corev1.VolumeMount{
			{Name: socketVolumeName, MountPath: l7CollectorSocketMountPath},
		},
	}

	volumes := []corev1.Volume{
		{
			Name:         socketVolumeName,
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
		},
		{
			Name: felixVolumeName,
			VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{Driver: "csi.tigera.io"},
			},
		},
	}

	overlay := map[string]interface{}{
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"volumes":    volumes,
					"containers": []corev1.Container{istioProxyPatch, sidecar},
				},
			},
		},
	}

	out, err := yaml.Marshal(overlay)
	if err != nil {
		// yaml.Marshal on well-formed core types is not expected to fail.
		panic(fmt.Errorf("failed to marshal waypoint deployment overlay: %w", err))
	}
	return string(out)
}

// renderALSEnvoyFilter builds the EnvoyFilter that enables gRPC ALS access
// logging on the waypoint proxy's main_internal listener, streaming logs to
// the l7-collector sidecar via the shared unix socket.
func renderALSEnvoyFilter(namespace string) *EnvoyFilter {
	return &EnvoyFilter{
		TypeMeta: metav1.TypeMeta{
			APIVersion: envoyFilterGV.String(),
			Kind:       "EnvoyFilter",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      L7WaypointALSFilterName,
			Namespace: namespace,
		},
		Spec: map[string]interface{}{
			// Attach mesh-wide to all waypoints. Istio's policy attachment
			// (pilot/pkg/model/policyattachment.go) only matches waypoint
			// proxies when the EnvoyFilter lives in the root namespace and
			// carries a targetRef of kind GatewayClass with name
			// "istio-waypoint". workloadSelector with the class-name label
			// is silently ignored for waypoint internal listeners.
			"targetRefs": []interface{}{
				map[string]interface{}{
					"kind":  "GatewayClass",
					"group": "gateway.networking.k8s.io",
					"name":  IstioWaypointGatewayClass,
				},
			},
			"configPatches": []interface{}{
				map[string]interface{}{
					"applyTo": "NETWORK_FILTER",
					"match": map[string]interface{}{
						"listener": map[string]interface{}{
							"name": "main_internal",
							"filterChain": map[string]interface{}{
								"filter": map[string]interface{}{
									"name": "envoy.filters.network.http_connection_manager",
								},
							},
						},
					},
					"patch": map[string]interface{}{
						"operation": "MERGE",
						"value": map[string]interface{}{
							"typed_config": map[string]interface{}{
								"@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
								"access_log": []interface{}{
									map[string]interface{}{
										"name": "envoy.access_loggers.http_grpc",
										"typed_config": map[string]interface{}{
											"@type": "type.googleapis.com/envoy.extensions.access_loggers.grpc.v3.HttpGrpcAccessLogConfig",
											"common_config": map[string]interface{}{
												"log_name": "tigera_l7",
												"grpc_service": map[string]interface{}{
													"google_grpc": map[string]interface{}{
														"target_uri":  l7CollectorSocketURI,
														"stat_prefix": "l7_waypoint_als",
													},
												},
												"transport_api_version": "V3",
												"filter_state_objects_to_log": []interface{}{
													forwardedFilterStateKey,
												},
											},
											"additional_request_headers_to_log": []interface{}{
												"x-forwarded-for",
												"x-envoy-external-address",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// renderSrcPortEnvoyFilter builds the EnvoyFilter that captures the original
// client IP from the Forwarded header (set by ztunnel on the HBONE CONNECT
// request) on the connect_terminate listener and propagates it as filter
// state to main_internal.
func renderSrcPortEnvoyFilter(namespace string) *EnvoyFilter {
	return &EnvoyFilter{
		TypeMeta: metav1.TypeMeta{
			APIVersion: envoyFilterGV.String(),
			Kind:       "EnvoyFilter",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      L7WaypointSrcPortFilterName,
			Namespace: namespace,
		},
		Spec: map[string]interface{}{
			// See renderALSEnvoyFilter — waypoints require a targetRef of
			// kind GatewayClass in the root namespace; workloadSelector does
			// not reach the waypoint's connect_terminate listener.
			"targetRefs": []interface{}{
				map[string]interface{}{
					"kind":  "GatewayClass",
					"group": "gateway.networking.k8s.io",
					"name":  IstioWaypointGatewayClass,
				},
			},
			"configPatches": []interface{}{
				map[string]interface{}{
					"applyTo": "HTTP_FILTER",
					"match": map[string]interface{}{
						"listener": map[string]interface{}{
							"name": "connect_terminate",
							"filterChain": map[string]interface{}{
								"filter": map[string]interface{}{
									"name": "envoy.filters.network.http_connection_manager",
									"subFilter": map[string]interface{}{
										"name": "connect_authority",
									},
								},
							},
						},
					},
					"patch": map[string]interface{}{
						"operation": "INSERT_AFTER",
						"value": map[string]interface{}{
							"name": "tigera.forwarded_header",
							"typed_config": map[string]interface{}{
								"@type": "type.googleapis.com/envoy.extensions.filters.http.set_filter_state.v3.Config",
								"on_request_headers": []interface{}{
									map[string]interface{}{
										"object_key": forwardedFilterStateKey,
										"format_string": map[string]interface{}{
											"text_format_source": map[string]interface{}{
												"inline_string": "%REQ(forwarded)%",
											},
										},
										"shared_with_upstream": "ONCE",
										"factory_key":          "envoy.string",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
