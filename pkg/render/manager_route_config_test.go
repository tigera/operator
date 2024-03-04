// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package render_test

import (
	"bytes"
	"encoding/json"

	"github.com/google/go-cmp/cmp"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
)

var _ = Describe("VoltronRouteConfigBuilder", func() {
	var (
		builder render.VoltronRouteConfigBuilder

		route                      operatorv1.TLSTerminatedRoute
		routesConfigMapVolumeMount corev1.VolumeMount
		routesConfigMapVolume      corev1.Volume
		routesConfigMap            *corev1.ConfigMap

		caBundle            *corev1.ConfigMap
		caBundleVolumeMount corev1.VolumeMount
		caBundleVolume      corev1.Volume

		mtlsCert *corev1.Secret
		mtlsKey  *corev1.Secret

		mtlsCertVolumeMount corev1.VolumeMount
		mtlsCertVolume      corev1.Volume

		mtlsKeyVolumeMount corev1.VolumeMount
		mtlsKeyVolume      corev1.Volume
	)

	BeforeEach(func() {
		builder = render.NewVoltronRouteConfigBuilder()

		route = operatorv1.TLSTerminatedRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "tigera-manager"},
			Spec: operatorv1.TLSTerminatedRouteSpec{
				PathMatch: &operatorv1.PathMatch{
					Path:        "/foobar",
					PathRegexp:  ptr.ToPtr("^/foobar$"),
					PathReplace: ptr.ToPtr("/"),
				},
			},
		}

		routesConfigMapVolumeMount = corev1.VolumeMount{
			Name: "cm-voltron-routes", MountPath: "/config_maps/voltron-routes", ReadOnly: true,
		}

		routesConfigMapVolume = corev1.Volume{
			Name: "cm-voltron-routes",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "voltron-routes"},
					DefaultMode:          ptr.ToPtr(int32(420)),
				},
			},
		}

		routesConfigMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "voltron-routes", Namespace: "tigera-manager"},
			Data:       map[string]string{},
		}

		caBundle = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: "ca-bundle",
			},
			Data: map[string]string{
				"bundle": "bundle",
			},
		}

		caBundleVolumeMount = corev1.VolumeMount{Name: "cm-ca-bundle", MountPath: "/config_maps/ca-bundle", ReadOnly: true}
		caBundleVolume = corev1.Volume{
			Name: "cm-ca-bundle",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "ca-bundle"},
					DefaultMode:          ptr.ToPtr(int32(420)),
				},
			},
		}

		mtlsCert = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mtls-cert",
				Namespace: "tigera-manager",
			},
			Data: map[string][]byte{
				"cert.pem": []byte("certbytes"),
			},
		}

		mtlsCertVolumeMount = corev1.VolumeMount{Name: "scrt-mtls-cert", MountPath: "/secrets/mtls-cert", ReadOnly: true}
		mtlsCertVolume = corev1.Volume{
			Name: "scrt-mtls-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  mtlsCert.Name,
					DefaultMode: ptr.ToPtr(int32(420)),
				},
			},
		}

		mtlsKey = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "mtls-key",
				Namespace: "tigera-manager",
			},
			Data: map[string][]byte{
				"key.pem": []byte("keybytes"),
			},
		}

		mtlsKeyVolumeMount = corev1.VolumeMount{Name: "scrt-mtls-key", MountPath: "/secrets/mtls-key", ReadOnly: true}

		mtlsKeyVolume = corev1.Volume{
			Name: "scrt-mtls-key",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  mtlsKey.Name,
					DefaultMode: ptr.ToPtr(int32(420)),
				},
			},
		}
	})

	Context("TLSTerminatedRoutes", func() {
		When("the CABundle is not set", func() {
			It("returns an error", func() {
				builder.AddTLSTerminatedRoute(route)

				_, err := builder.Build()
				Expect(err).Should(HaveOccurred())
			})
		})

		When("the CABundle is set but the config map was not added to the builder", func() {
			It("returns an error", func() {
				route.Spec.CABundle = &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "ca-bundle",
					},
					Key: "ca.bundle",
				}
				builder.AddTLSTerminatedRoute(route)

				_, err := builder.Build()
				Expect(err).Should(HaveOccurred())
			})
		})

		When("the CABundle is set and the config map was added to the builder", func() {
			DescribeTable("successfully builds the config", func(target operatorv1.TargetType, fileName string) {
				route.Spec.Target = target
				route.Spec.CABundle = &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "ca-bundle",
					},
					Key: "ca.bundle",
				}

				builder.AddTLSTerminatedRoute(route)

				builder.AddConfigMap(caBundle)

				config, err := builder.Build()
				Expect(err).ShouldNot(HaveOccurred())

				key, value := config.Annotation()
				Expect(key).Should(Equal("hash.operator.tigera.io/route-configuration"))
				Expect(value).ShouldNot(BeEmpty())
				Expect(config.VolumeMounts()).Should(Equal([]corev1.VolumeMount{caBundleVolumeMount, routesConfigMapVolumeMount}))

				Expect(config.Volumes()).Should(Equal([]corev1.Volume{caBundleVolume, routesConfigMapVolume}))

				cm := config.RoutesConfigMap("tigera-manager")
				cm.Data[fileName] = compactJsonString(cm.Data[fileName])

				routesConfigMap.Data[fileName] = `[{"destination":"","path":"/foobar","caBundlePath":"/config_maps/ca-bundle/ca.bundle","pathRegexp":"^/foobar$","pathReplace":"/"}]`
				Expect(cm).Should(Equal(routesConfigMap))
			},
				Entry("UI target", operatorv1.TargetTypeUI, "uiTLSTerminatedRoutes.json"),
				Entry("Upstream tunnel target", operatorv1.TargetTypeUpstreamTunnel, "upstreamTunnelTLSTerminatedRoutes.json"),
			)
		})

		When("the MTLS cert is specified", func() {
			BeforeEach(func() {
				route.Spec.CABundle = &corev1.ConfigMapKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "ca-bundle",
					},
					Key: "ca.bundle",
				}
			})

			It("returns an error if the MTLS key is not specified", func() {
				route.Spec.Target = operatorv1.TargetTypeUI
				route.Spec.MTLSCert = &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: mtlsCert.Name,
					},
					Key: "cert.pem",
				}

				builder.AddTLSTerminatedRoute(route)
				builder.AddConfigMap(caBundle)
				builder.AddSecret(mtlsCert)

				_, err := builder.Build()
				Expect(err).Should(HaveOccurred())
			})

			DescribeTable("succeeds if the MTLS key is specified", func(target operatorv1.TargetType, fileName string) {
				route.Spec.Target = target
				route.Spec.MTLSCert = &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: mtlsCert.Name,
					},
					Key: "cert.pem",
				}
				route.Spec.MTLSKey = &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: mtlsKey.Name,
					},
					Key: "key.pem",
				}

				builder.AddTLSTerminatedRoute(route)
				builder.AddConfigMap(caBundle)
				builder.AddSecret(mtlsCert)
				builder.AddSecret(mtlsKey)

				config, err := builder.Build()
				Expect(err).ShouldNot(HaveOccurred())

				key, value := config.Annotation()
				Expect(key).Should(Equal("hash.operator.tigera.io/route-configuration"))
				Expect(value).ShouldNot(BeEmpty())
				Expect(config.VolumeMounts()).Should(Equal([]corev1.VolumeMount{caBundleVolumeMount, mtlsCertVolumeMount, mtlsKeyVolumeMount, routesConfigMapVolumeMount}))

				Expect(config.Volumes()).Should(Equal([]corev1.Volume{caBundleVolume, mtlsCertVolume, mtlsKeyVolume, routesConfigMapVolume}), cmp.Diff(config.Volumes(), []corev1.Volume{caBundleVolume, mtlsCertVolume, mtlsKeyVolume, routesConfigMapVolume}))

				cm := config.RoutesConfigMap("tigera-manager")
				cm.Data[fileName] = compactJsonString(cm.Data[fileName])

				routesConfigMap.Data[fileName] = `[{"destination":"","path":"/foobar","caBundlePath":"/config_maps/ca-bundle/ca.bundle","pathRegexp":"^/foobar$","pathReplace":"/","clientCertPath":"/config_maps/mtls-cert/cert.pem","clientKeyPath":"/config_maps/mtls-key/key.pem"}]`
				Expect(cm).Should(Equal(routesConfigMap))
			},
				Entry("UI target", operatorv1.TargetTypeUI, "uiTLSTerminatedRoutes.json"),
				Entry("Upstream tunnel target", operatorv1.TargetTypeUpstreamTunnel, "upstreamTunnelTLSTerminatedRoutes.json"),
			)
		})
	})
})

func compactJsonString(jsonStr string) string {
	buffer := new(bytes.Buffer)
	Expect(json.Compact(buffer, []byte(jsonStr))).ShouldNot(HaveOccurred())
	return buffer.String()
}
