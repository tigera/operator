// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.

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

package cloudconfig

import (
	"strconv"

	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CloudConfig ConfigMap tests", func() {
	Context("NewCloudConfigFromConfigMap", func() {
		var configMap *corev1.ConfigMap

		BeforeEach(func() {
			configMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      CloudConfigConfigMapName,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string]string{
					"tenantId":             "abc123",
					"tenantName":           "tenant1",
					"externalESDomain":     "externalES.com",
					"externalKibanaDomain": "externalKibana.com",
					"enableMTLS":           strconv.FormatBool(false),
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
	})

	Context("ToTenant", func() {
		var cloudConfig *CloudConfig

		BeforeEach(func() {
			cloudConfig = &CloudConfig{
				tenantId:             "abc123",
				tenantName:           "tenant1",
				externalESDomain:     "externalES.com",
				externalKibanaDomain: "externalKibana.com",
				enableMTLS:           true,
			}
		})

		It("should return a single-tenant Tenant with the Elastic configuration from the CloudConfig", func() {
			tenant := cloudConfig.ToTenant()
			Expect(tenant.Name).To(Equal("default"))
			Expect(tenant.Namespace).To(BeEmpty())
			Expect(tenant.MultiTenant()).To(BeFalse())
			Expect(tenant.Spec.ID).To(Equal("abc123"))
			Expect(tenant.Spec.Name).To(Equal("tenant1"))
			Expect(tenant.Spec.Elastic.URL).To(Equal("https://externalES.com:443"))
			Expect(tenant.Spec.Elastic.KibanaURL).To(Equal("https://externalKibana.com:443"))
			Expect(tenant.Spec.Elastic.MutualTLS).To(BeTrue())
		})

		It("should not declare any indices when not using single-index storage", func() {
			Expect(cloudConfig.ToTenant().Spec.Indices).To(BeEmpty())
		})

		It("should declare the standard index for every data type when using single-index storage", func() {
			indices := cloudConfig.ToTenant(WithStandardIndices()).Spec.Indices
			Expect(indices).To(HaveLen(len(v1.DataTypes)))
			for _, index := range indices {
				Expect(index.BaseIndexName).To(Equal(cloudStandardIndices[index.DataType]))
				Expect(index.BaseIndexName).ToNot(BeEmpty())
			}
		})

		It("should declare indices in a stable order", func() {
			expected := cloudConfig.ToTenant(WithStandardIndices()).Spec.Indices
			for i := 0; i < 10; i++ {
				Expect(cloudConfig.ToTenant(WithStandardIndices()).Spec.Indices).To(Equal(expected))
			}
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
			}
		})

		It("should return a valid ConfigMap from CloudConfig", func() {
			expectedConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      CloudConfigConfigMapName,
					Namespace: common.OperatorNamespace(),
				},
				Data: map[string]string{
					"tenantId":             "abc123",
					"tenantName":           "tenant1",
					"externalESDomain":     "externalES.com",
					"externalKibanaDomain": "externalKibana.com",
					"enableMTLS":           strconv.FormatBool(false),
				},
			}
			cm := cloudConfig.ConfigMap()
			Expect(cm).Should(Equal(expectedConfigMap))
		})
	})
})
