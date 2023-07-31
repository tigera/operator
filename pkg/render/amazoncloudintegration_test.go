// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

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
	"fmt"

	"github.com/tigera/operator/pkg/common"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	rtest "github.com/tigera/operator/pkg/render/common/test"
)

const (
	AwsCIName = "tigera-amazon-cloud-integration"
	AwsCINs   = "tigera-amazon-cloud-integration"
)

var _ = Describe("AmazonCloudIntegration rendering tests", func() {
	var instance *operatorv1.AmazonCloudIntegration
	var credential *render.AmazonCredential
	var cfg *render.AmazonCloudIntegrationConfiguration

	BeforeEach(func() {
		instance = &operatorv1.AmazonCloudIntegration{
			Spec: operatorv1.AmazonCloudIntegrationSpec{
				DefaultPodMetadataAccess:     operatorv1.MetadataAccessDenied,
				NodeSecurityGroupIDs:         []string{"sg-nodeid"},
				PodSecurityGroupID:           "sg-podsgid",
				VPCS:                         []string{"vpc-id"},
				SQSURL:                       "sqs://aws.some.host",
				AWSRegion:                    "us-west-2",
				EnforcedSecurityGroupID:      "sg-enforcedsgid",
				TrustEnforcedSecurityGroupID: "sg-trustenforcedsgid",
			},
		}

		credential = &render.AmazonCredential{
			KeyId:     []byte("KeyId"),
			KeySecret: []byte("KeySecret"),
		}

		scheme := runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		cli := fake.NewClientBuilder().WithScheme(scheme).Build()

		certificateManager, err := certificatemanager.Create(cli, nil, clusterDomain, common.OperatorNamespace())
		Expect(err).NotTo(HaveOccurred())
		trustedCaBundle, err := certificateManager.CreateTrustedBundleWithSystemRootCertificates()
		Expect(err).NotTo(HaveOccurred())

		cfg = &render.AmazonCloudIntegrationConfiguration{
			AmazonCloudIntegration: instance,
			Installation:           &operatorv1.InstallationSpec{},
			Credentials:            credential,
			TrustedBundle:          trustedCaBundle,
		}
	})

	It("should render controlPlaneNodeSelector", func() {
		cfg.Installation = &operatorv1.InstallationSpec{
			ControlPlaneNodeSelector: map[string]string{"foo": "bar"},
		}
		component := render.AmazonCloudIntegration(cfg)
		resources, _ := component.Objects()
		resource := rtest.GetResource(resources, AwsCIName, AwsCINs, "apps", "v1", "Deployment")
		d := resource.(*appsv1.Deployment)
		Expect(d.Spec.Template.Spec.NodeSelector).To(Equal(map[string]string{"foo": "bar"}))
	})

	It("should render an AmazonCloudConfiguration with specified configuration", func() {
		component := render.AmazonCloudIntegration(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()

		// Should render the correct resources.
		// - 1 namespace
		// - 1 Service account
		// - 2 ClusterRole and binding
		// - 1 Credential secret
		// - 1 ConfigMap
		// - 1 Deployment
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: AwsCINs, ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: AwsCIName, ns: AwsCINs, group: "", version: "v1", kind: "ServiceAccount"},
			{name: AwsCIName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: AwsCIName, ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "amazon-cloud-integration-credentials", ns: AwsCINs, group: "", version: "v1", kind: "Secret"},
			{name: "tigera-ca-bundle", ns: "tigera-amazon-cloud-integration", group: "", version: "v1", kind: "ConfigMap"},
			{name: AwsCIName, ns: AwsCINs, group: "apps", version: "v1", kind: "Deployment"},
		}

		Expect(resources).To(HaveLen(len(expectedResources)))
		for i, expectedRes := range expectedResources {
			rtest.ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
		}

		resource := rtest.GetResource(resources, AwsCIName, AwsCINs, "apps", "v1", "Deployment")
		d := resource.(*appsv1.Deployment)

		Expect(d.Name).To(Equal(AwsCIName))

		Expect(*d.Spec.Replicas).To(BeEquivalentTo(1))
		Expect(d.Spec.Strategy.Type).To(Equal(appsv1.RecreateDeploymentStrategyType))

		Expect(d.Spec.Template.Name).To(Equal(AwsCIName))
		Expect(d.Spec.Template.Namespace).To(Equal(AwsCINs))

		Expect(d.Spec.Template.Spec.NodeSelector).To(HaveLen(0))

		Expect(d.Spec.Template.Spec.ServiceAccountName).To(Equal(AwsCIName))

		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(rmeta.TolerateAll))

		Expect(d.Spec.Template.Spec.ImagePullSecrets).To(BeEmpty())
		Expect(d.Spec.Template.ObjectMeta.Annotations).To(HaveKey("hash.operator.tigera.io/credential-secret"))
		Expect(d.Spec.Template.Spec.Containers).To(HaveLen(1))
		container := d.Spec.Template.Spec.Containers[0]
		Expect(container.Name).To(Equal(AwsCIName))
		Expect(container.Image).To(Equal(
			fmt.Sprintf("%s%s:%s", components.TigeraRegistry, components.ComponentCloudControllers.Image, components.ComponentCloudControllers.Version),
		))

		for k, v := range cfg.TrustedBundle.HashAnnotations() {
			Expect(d.Spec.Template.Annotations).To(HaveKeyWithValue(k, v))
		}
		Expect(container.VolumeMounts).To(Equal(
			[]corev1.VolumeMount{
				{Name: "tigera-ca-bundle", MountPath: "/etc/pki/tls/certs", ReadOnly: true},
				{Name: "tigera-ca-bundle", MountPath: "/etc/pki/tls/cert.pem", SubPath: "ca-bundle.crt", ReadOnly: true},
			}))
		Expect(d.Spec.Template.Spec.Volumes).To(Equal(
			[]corev1.Volume{
				{Name: "tigera-ca-bundle",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "tigera-ca-bundle",
							},
						},
					}},
			},
		))

		Expect(container.Args).To(BeNil())
		envs := container.Env

		// DefaultPodMetadataAccess:     operatorv1.MetadataAccessDenied,
		env := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "FAILSAFE_CONTROLLER_APP_NAME", Value: AwsCIName},
			{Name: "CLOUDWATCH_HEALTHREPORTING_ENABLED", Value: "false"},
			{Name: "VPCS", Value: "vpc-id"},
			{Name: "SQS_URL", Value: "sqs://aws.some.host"},
			{Name: "AWS_REGION", Value: "us-west-2"},
			{Name: "TIGERA_ENFORCED_GROUP_ID", Value: "sg-enforcedsgid"},
			{Name: "TIGERA_TRUST_ENFORCED_GROUP_ID", Value: "sg-trustenforcedsgid"},
			{Name: "AWS_SECRET_ACCESS_KEY", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "amazon-cloud-integration-credentials",
					},
					Key: "key-secret",
				},
			}},
			{Name: "AWS_ACCESS_KEY_ID", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "amazon-cloud-integration-credentials",
					},
					Key: "key-id",
				},
			}},
		}
		Expect(envs).To(HaveLen(len(env)))
		Expect(envs).To(ConsistOf(env))

		Expect(container.ReadinessProbe.Exec.Command).To(ConsistOf([]string{"check-status", "-r"}))
		Expect(container.ReadinessProbe.InitialDelaySeconds).To(BeEquivalentTo(10))
		Expect(container.ReadinessProbe.PeriodSeconds).To(BeEquivalentTo(10))
		Expect(container.ReadinessProbe.FailureThreshold).To(BeEquivalentTo(3))

		Expect(*container.SecurityContext.AllowPrivilegeEscalation).To(BeFalse())
		Expect(*container.SecurityContext.Privileged).To(BeFalse())
		Expect(*container.SecurityContext.RunAsGroup).To(BeEquivalentTo(10001))
		Expect(*container.SecurityContext.RunAsNonRoot).To(BeTrue())
		Expect(*container.SecurityContext.RunAsUser).To(BeEquivalentTo(10001))
		Expect(container.SecurityContext.Capabilities).To(Equal(
			&corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
			},
		))
		Expect(container.SecurityContext.SeccompProfile).To(Equal(
			&corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			}))

	})

	It("should set MetadataAccess when configured", func() {
		cfg.AmazonCloudIntegration.Spec.DefaultPodMetadataAccess = operatorv1.MetadataAccessAllowed
		component := render.AmazonCloudIntegration(cfg)
		Expect(component.ResolveImages(nil)).To(BeNil())

		resources, _ := component.Objects()

		resource := rtest.GetResource(resources, AwsCIName, AwsCINs, "apps", "v1", "Deployment")
		Expect(resource).ToNot(BeNil())
		d := resource.(*appsv1.Deployment)

		Expect(d.Name).To(Equal(AwsCIName))

		container := d.Spec.Template.Spec.Containers[0]
		Expect(container.Name).To(Equal(AwsCIName))

		envs := container.Env

		env := []corev1.EnvVar{
			{Name: "DATASTORE_TYPE", Value: "kubernetes"},
			{Name: "FAILSAFE_CONTROLLER_APP_NAME", Value: AwsCIName},
			{Name: "CLOUDWATCH_HEALTHREPORTING_ENABLED", Value: "false"},
			{Name: "VPCS", Value: "vpc-id"},
			{Name: "SQS_URL", Value: "sqs://aws.some.host"},
			{Name: "AWS_REGION", Value: "us-west-2"},
			{Name: "TIGERA_ENFORCED_GROUP_ID", Value: "sg-enforcedsgid"},
			{Name: "TIGERA_TRUST_ENFORCED_GROUP_ID", Value: "sg-trustenforcedsgid"},
			{Name: "AWS_SECRET_ACCESS_KEY", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "amazon-cloud-integration-credentials",
					},
					Key: "key-secret",
				},
			}},
			{Name: "AWS_ACCESS_KEY_ID", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "amazon-cloud-integration-credentials",
					},
					Key: "key-id",
				},
			}},
			{Name: "ALLOW_POD_METADATA_ACCESS", Value: "true"},
		}
		Expect(envs).To(HaveLen(len(env)))
		Expect(envs).To(ConsistOf(env))

	})
})
