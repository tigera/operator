package utils

import (
	"context"
	"fmt"
	"strconv"

	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/render/common/cloudconfig"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	admissionv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CloudConfig utils tests", func() {
	Context("GetCloudConfig", func() {
		var (
			cli    client.Client
			ctx    context.Context
			scheme *runtime.Scheme
		)
		BeforeEach(func() {
			scheme = runtime.NewScheme()
			Expect(apis.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(storagev1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(appsv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(batchv1beta.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())
			Expect(admissionv1beta1.SchemeBuilder.AddToScheme(scheme)).ShouldNot(HaveOccurred())

			ctx = context.Background()
			cli = fake.NewFakeClientWithScheme(scheme)
		})

		It("should return an error after failing to find the ConfigMap", func() {
			cloudConfig, err := GetCloudConfig(ctx, cli)
			Expect(cloudConfig).Should(BeNil())
			Expect(err).Should(HaveOccurred())
		})

		It("should retrieve the CloudConfig struct with all fields populated from the ConfigMap", func() {
			Expect(cli.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      cloudconfig.CloudConfigConfigMapName,
					Namespace: rmeta.OperatorNamespace(),
				},
				Data: map[string]string{
					"tenantId":             "abc123",
					"tenantName":           "tenant1",
					"externalESDomain":     "externalES.com",
					"externalKibanaDomain": "externalKibana.com",
					"enableMTLS":           strconv.FormatBool(false),
				}})).To(BeNil())

			cloudConfig, err := GetCloudConfig(ctx, cli)
			fmt.Printf("cloudConfig: %+v", cloudConfig)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cloudConfig.TenantId()).Should(Equal("abc123"))
			Expect(cloudConfig.TenantName()).Should(Equal("tenant1"))
			Expect(cloudConfig.ExternalESDomain()).Should(Equal("externalES.com"))
			Expect(cloudConfig.ExternalKibanaDomain()).Should(Equal("externalKibana.com"))
			Expect(cloudConfig.EnableMTLS()).Should(BeFalse())
		})
	})
})
