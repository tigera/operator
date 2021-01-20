// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
)

const (
	AwsCIName = "tigera-amazon-cloud-integration"
	AwsCINs   = "tigera-amazon-cloud-integration"
)

var _ = Describe("AmazonCloudIntegration rendering tests", func() {
	var instance *operator.AmazonCloudIntegration
	var credential *render.AmazonCredential
	var installation *operator.InstallationSpec

	BeforeEach(func() {
		instance = &operator.AmazonCloudIntegration{
			Spec: operator.AmazonCloudIntegrationSpec{
				DefaultPodMetadataAccess:     operator.MetadataAccessDenied,
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

		installation = &operator.InstallationSpec{}
	})

	It("should render an AmazonCloudConfiguration with specified configuration", func() {
		// AmazonCloudIntegration(aci *operatorv1.AmazonCloudIntegration, installation *operator.Installation, cred *AmazonCredential, ps []*corev1.Secret, openshift bool) (Component, error) {
		component, err := render.AmazonCloudIntegration(instance, installation, credential, nil, openshift)
		Expect(err).To(BeNil(), "Expected AmazonCloudIntegration to create successfully %s", err)

		resources, _ := component.Objects()

		// Should render the correct resources.
		// - 1 namespace
		// - 1 Service account
		// - 2 ClusterRole and binding
		// - 1 Credential secret
		// - 1 Deployment
		Expect(len(resources)).To(Equal(6))
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
			{name: AwsCIName, ns: AwsCINs, group: "", version: "v1", kind: "Deployment"},
		}

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		resource := GetResource(resources, AwsCIName, AwsCINs, "", "v1", "Deployment")
		d := resource.(*v1.Deployment)

		Expect(d.Name).To(Equal(AwsCIName))
		Expect(len(d.Labels)).To(Equal(1))
		Expect(d.Labels).To(HaveKeyWithValue("k8s-app", AwsCIName))

		Expect(*d.Spec.Replicas).To(BeEquivalentTo(1))
		Expect(d.Spec.Strategy.Type).To(Equal(v1.RecreateDeploymentStrategyType))
		Expect(len(d.Spec.Selector.MatchLabels)).To(Equal(1))
		Expect(d.Spec.Selector.MatchLabels).To(HaveKeyWithValue("k8s-app", AwsCIName))

		Expect(d.Spec.Template.Name).To(Equal(AwsCIName))
		Expect(d.Spec.Template.Namespace).To(Equal(AwsCINs))
		Expect(len(d.Spec.Template.Labels)).To(Equal(1))
		Expect(d.Spec.Template.Labels).To(HaveKeyWithValue("k8s-app", AwsCIName))

		Expect(len(d.Spec.Template.Spec.NodeSelector)).To(Equal(0))

		Expect(d.Spec.Template.Spec.ServiceAccountName).To(Equal(AwsCIName))

		expectedTolerations := []corev1.Toleration{
			{Operator: "Exists", Effect: "NoSchedule"},
			{Operator: "Exists", Effect: "NoExecute"},
			{Operator: "Exists", Key: "CriticalAddonsOnly"},
		}
		Expect(d.Spec.Template.Spec.Tolerations).To(ConsistOf(expectedTolerations))

		Expect(d.Spec.Template.Spec.ImagePullSecrets).To(BeEmpty())
		Expect(d.Spec.Template.ObjectMeta.Annotations).To(HaveKey("hash.operator.tigera.io/credential-secret"))
		Expect(len(d.Spec.Template.Spec.Containers)).To(Equal(1))
		container := d.Spec.Template.Spec.Containers[0]
		Expect(container.Name).To(Equal(AwsCIName))
		Expect(container.Image).To(Equal(
			fmt.Sprintf("%s%s:%s", components.TigeraRegistry, components.ComponentCloudControllers.Image, components.ComponentCloudControllers.Version),
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

		Expect(*(container.SecurityContext.RunAsNonRoot)).To(BeTrue())
		Expect(*(container.SecurityContext.AllowPrivilegeEscalation)).To(BeFalse())

	})

	It("should set MetadataAccess when configured", func() {
		instance.Spec.DefaultPodMetadataAccess = operator.MetadataAccessAllowed
		component, err := render.AmazonCloudIntegration(instance, installation, credential, nil, openshift)
		Expect(err).To(BeNil(), "Expected AmazonCloudIntegration to create successfully %s", err)

		resources, _ := component.Objects()

		resource := GetResource(resources, AwsCIName, AwsCINs, "", "v1", "Deployment")
		Expect(resource).ToNot(BeNil())
		d := resource.(*v1.Deployment)

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
