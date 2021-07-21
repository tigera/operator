package cloudconfig

import (
	"strconv"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CloudConfig ConfigMap tests", func() {
	Context("NewCloudConfigFromConfigMap", func() {
		var configMap *corev1.ConfigMap

		BeforeEach(func() {
			configMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      CloudConfigConfigMapName,
					Namespace: rmeta.OperatorNamespace(),
				},
				Data: map[string]string{
					"tenantId":             "abc123",
					"tenantName":           "tenant1",
					"externalESDomain":     "externalES.com",
					"externalKibanaDomain": "externalKibana.com",
					"enableMTLS":           strconv.FormatBool(false),
					"useCA":                strconv.FormatBool(false),
				},
			}
		})

		It("should return a valid CloudConfig", func() {
			expectedCloudConfig := &CloudConfig{
				tenantId:             "abc123",
				tenantName:           "tenant1",
				externalESDomain:     "externalES.com",
				externalKibanaDomain: "externalKibana.com",
				enableMTLS:           false,
				useCA:                false,
			}

			cc, err := NewCloudConfigFromConfigMap(configMap)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(cc).Should(Equal(expectedCloudConfig))
		})

		It("should return an error when tenantId is not set", func() {
			configMap.Data["tenantId"] = ""
			_, err := NewCloudConfigFromConfigMap(configMap)
			Expect(err).Should(HaveOccurred())
		})

		It("should return an error when tenantName is not set", func() {
			configMap.Data["tenantName"] = ""
			_, err := NewCloudConfigFromConfigMap(configMap)
			Expect(err).Should(HaveOccurred())
		})

		It("should return an error when externalESDomain is not set", func() {
			configMap.Data["externalESDomain"] = ""
			_, err := NewCloudConfigFromConfigMap(configMap)
			Expect(err).Should(HaveOccurred())
		})

		It("should return an error when externalKibanaDomain is not set", func() {
			configMap.Data["externalKibanaDomain"] = ""
			_, err := NewCloudConfigFromConfigMap(configMap)
			Expect(err).Should(HaveOccurred())
		})

		It("should return an error when enableMTLS is not a valid boolean", func() {
			configMap.Data["enableMTLS"] = "truee"
			_, err := NewCloudConfigFromConfigMap(configMap)
			Expect(err).Should(HaveOccurred())
		})

		It("should return an error when useCA is not a valid boolean", func() {
			configMap.Data["useCA"] = "falsee"
			_, err := NewCloudConfigFromConfigMap(configMap)
			Expect(err).Should(HaveOccurred())
		})
	})

	Context("ConfigMap from CloudConfig", func() {
		var cloudConfig *CloudConfig

		BeforeEach(func() {
			cloudConfig = &CloudConfig{
				tenantId:             "abc123",
				tenantName:           "tenant1",
				externalESDomain:     "externalES.com",
				externalKibanaDomain: "externalKibana.com",
				enableMTLS:           false,
				useCA:                false,
			}
		})

		It("should return a valid ConfigMap from CloudConfig", func() {
			expectedConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      CloudConfigConfigMapName,
					Namespace: rmeta.OperatorNamespace(),
				},
				Data: map[string]string{
					"tenantId":             "abc123",
					"tenantName":           "tenant1",
					"externalESDomain":     "externalES.com",
					"externalKibanaDomain": "externalKibana.com",
					"enableMTLS":           strconv.FormatBool(false),
					"useCA":                strconv.FormatBool(false),
				},
			}
			cm := cloudConfig.ConfigMap()
			Expect(cm).Should(Equal(expectedConfigMap))
		})
	})
})
