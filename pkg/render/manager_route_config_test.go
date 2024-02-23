package render_test

import (
	"github.com/google/go-cmp/cmp"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/ptr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
)

var _ = FDescribe("VoltronRouteConfigBuilder", func() {
	var builder render.VoltronRouteConfigBuilder

	BeforeEach(func() {
		builder = render.NewVoltronRouteConfigBuilder()
	})

	Context("TLSTerminatedRoutes", func() {
		When("TLSTerminatedRoute with allow insecure set and no CAs or MTLS config", func() {
			It("builds the route configuration without mounting any CA bundles or cert key pairs", func() {
				builder.AddTLSTerminatedRoute(operatorv1.TLSTerminatedRoute{
					ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "tigera-manager"},
					Spec: operatorv1.TLSTerminatedRouteSpec{
						Target: operatorv1.TargetTypeUI,
						PathMatch: &operatorv1.PathMatch{
							Path:        "/foobar",
							PathRegexp:  "^/foobar$",
							PathReplace: "/",
						},
						AllowInsecureTLS: true,
					},
				})

				config, err := builder.Build()
				Expect(err).ShouldNot(HaveOccurred())

				key, value := config.Annotation()

				Expect(key).Should(Equal("hash.operator.tigera.io/route-configuration"))
				Expect(value).ShouldNot(BeEmpty())
				Expect(config.VolumeMounts()).Should(Equal([]corev1.VolumeMount{{
					Name: "voltron-routes", MountPath: "/routes", ReadOnly: true,
				}}))

				Expect(config.Volumes()).Should(Equal([]corev1.Volume{{
					Name: "voltron-routes",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "voltron-routes"},
							DefaultMode:          ptr.ToPtr(int32(420)),
						},
					},
				}}))

				expectedConfigMap := &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "voltron-routes", Namespace: "tigera-manager"},
					Data: map[string]string{
						"uiTLSTerminatedRoutes.json": `[{"destination":"","path":"/foobar","pathRegexp":"^/foobar$","pathReplace":"/","allowInsecureTLS":true}]`,
					},
				}
				Expect(config.RoutesConfigMap("tigera-manager")).Should(Equal(expectedConfigMap), cmp.Diff(config.RoutesConfigMap("tigera-manager"), expectedConfigMap))
			})
		})

		Context("AllowInsecure is set to false", func() {
			When("the CABundle is not set", func() {
				It("returns an error", func() {
					builder.AddTLSTerminatedRoute(operatorv1.TLSTerminatedRoute{
						ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "tigera-manager"},
						Spec: operatorv1.TLSTerminatedRouteSpec{
							Target: operatorv1.TargetTypeUI,
							PathMatch: &operatorv1.PathMatch{
								Path:        "/foobar",
								PathRegexp:  "^/foobar$",
								PathReplace: "/",
							},
							AllowInsecureTLS: true,
						},
					})

					_, err := builder.Build()
					Expect(err).Should(HaveOccurred())
				})
			})

			When("the CABundle is set but the config map was not added to the builder", func() {
				It("returns an error", func() {
					builder.AddTLSTerminatedRoute(operatorv1.TLSTerminatedRoute{
						ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "tigera-manager"},
						Spec: operatorv1.TLSTerminatedRouteSpec{
							Target: operatorv1.TargetTypeUI,
							PathMatch: &operatorv1.PathMatch{
								Path:        "/foobar",
								PathRegexp:  "^/foobar$",
								PathReplace: "/",
							},
							AllowInsecureTLS: true,
							CABundle: &corev1.ConfigMapKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "ca-bundle",
								},
								Key: "ca.bundle",
							},
						},
					})

					_, err := builder.Build()
					Expect(err).Should(HaveOccurred())
				})
			})

			When("the CABundle is set and the config map was  added to the builder", func() {
				FIt("successfully builds the config", func() {
					builder.AddTLSTerminatedRoute(operatorv1.TLSTerminatedRoute{
						ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "tigera-manager"},
						Spec: operatorv1.TLSTerminatedRouteSpec{
							Target: operatorv1.TargetTypeUI,
							PathMatch: &operatorv1.PathMatch{
								Path:        "/foobar",
								PathRegexp:  "^/foobar$",
								PathReplace: "/",
							},
							AllowInsecureTLS: true,
							CABundle: &corev1.ConfigMapKeySelector{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "ca-bundle",
								},
								Key: "ca.bundle",
							},
						},
					})

					builder.AddConfigMap(&corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{
							Name: "ca-bundle",
						},
						Data: map[string]string{
							"bundle": "bundle",
						},
					})

					config, err := builder.Build()
					Expect(err).ShouldNot(HaveOccurred())

					key, value := config.Annotation()

					Expect(key).Should(Equal("hash.operator.tigera.io/route-configuration"))
					Expect(value).ShouldNot(BeEmpty())
					Expect(config.VolumeMounts()).Should(Equal([]corev1.VolumeMount{
						{Name: "cm-ca-bundle", MountPath: "/config_maps/ca-bundle", ReadOnly: true},
						{Name: "cm-voltron-routes", MountPath: "/config_maps/voltron-routes", ReadOnly: true},
					}))

					Expect(config.Volumes()).Should(Equal([]corev1.Volume{
						{
							Name: "cm-ca-bundle",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: "ca-bundle"},
									DefaultMode:          ptr.ToPtr(int32(420)),
								},
							},
						},
						{
							Name: "cm-voltron-routes",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: "voltron-routes"},
									DefaultMode:          ptr.ToPtr(int32(420)),
								},
							},
						},
					}))

					expectedConfigMap := &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Name: "voltron-routes", Namespace: "tigera-manager"},
						Data: map[string]string{
							"uiTLSTerminatedRoutes.json": `[{"destination":"","path":"/foobar","caBundlePath":"/config_maps/ca-bundle/ca.bundle","pathRegexp":"^/foobar$","pathReplace":"/","allowInsecureTLS":true}]`,
						},
					}
					Expect(config.RoutesConfigMap("tigera-manager")).Should(Equal(expectedConfigMap), cmp.Diff(config.RoutesConfigMap("tigera-manager"), expectedConfigMap))
				})
			})
		})
	})

	Context("AddSecret", func() {
		It("adds a secret only once", func() {

		})
	})

	Context("AddTLSTerminatedRoute", func() {
		It("adds a tlsTerminatedRoute based on its target type", func() {

		})
	})

	Context("AddTLSPassThroughRoute", func() {
		It("adds a tlsPassThroughRoute", func() {

		})
	})

	Context("Build", func() {
		It("builds a Voltron route config and returns error when there any issues", func() {

		})
		It("builds a Voltron route config successfully when correct information is provided", func() {

		})
	})

	// Test the methods on the resulting VoltronRouteConfiguration similarly
})
