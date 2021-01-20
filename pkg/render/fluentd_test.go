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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	apps "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

var _ = Describe("Tigera Secure Fluentd rendering tests", func() {
	var instance *operatorv1.LogCollector
	var s3Creds *render.S3Credential
	var filters *render.FluentdFilters
	var eksConfig *render.EksCloudwatchLogConfig
	var installation *operatorv1.InstallationSpec
	var esConfigMap *render.ElasticsearchClusterConfig
	var splkCreds *render.SplunkCredential
	BeforeEach(func() {
		// Initialize a default instance to use. Each test can override this to its
		// desired configuration.
		instance = &operatorv1.LogCollector{}
		installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderNone,
		}
		s3Creds = nil
		filters = nil
		eksConfig = nil
		splkCreds = nil

		esConfigMap = render.NewElasticsearchClusterConfig("clusterTestName", 1, 1, 1)
	})

	It("should render with a default configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// Should render the correct resources.
		component := render.Fluentd(instance, nil, esConfigMap, s3Creds, splkCreds, filters, eksConfig, nil, installation)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*apps.DaemonSet)
		envs := ds.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []corev1.EnvVar{
			{Name: "FLUENT_UID", Value: "0"},
			{Name: "FLOW_LOG_FILE", Value: "/var/log/calico/flowlogs/flows.log"},
			{Name: "DNS_LOG_FILE", Value: "/var/log/calico/dnslogs/dns.log"},
			{Name: "FLUENTD_ES_SECURE", Value: "true"},
			{
				Name: "NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
				},
			},
		}
		for _, expected := range expectedEnvs {
			Expect(envs).To(ContainElement(expected))
		}
	})

	It("should render with S3 configuration", func() {
		s3Creds := &render.S3Credential{
			KeyId:     []byte("IdForTheKey"),
			KeySecret: []byte("SecretForTheKey"),
		}
		instance.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			S3: &operatorv1.S3StoreSpec{
				Region:     "anyplace",
				BucketName: "thebucket",
				BucketPath: "bucketpath",
			},
		}

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "log-collector-s3-credentials", ns: "tigera-fluentd", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// Should render the correct resources.
		component := render.Fluentd(instance, nil, esConfigMap, s3Creds, splkCreds, filters, eksConfig, nil, installation)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/s3-credentials"))
		envs := ds.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []struct {
			name       string
			val        string
			secretName string
			secretKey  string
		}{
			{"S3_STORAGE", "true", "", ""},
			{"S3_BUCKET_NAME", "thebucket", "", ""},
			{"AWS_REGION", "anyplace", "", ""},
			{"S3_BUCKET_PATH", "bucketpath", "", ""},
			{"S3_FLUSH_INTERVAL", "5s", "", ""},
			{"AWS_KEY_ID", "", "log-collector-s3-credentials", "key-id"},
			{"AWS_SECRET_KEY", "", "log-collector-s3-credentials", "key-secret"},
		}
		for _, expected := range expectedEnvs {
			if expected.val != "" {
				Expect(envs).To(ContainElement(corev1.EnvVar{Name: expected.name, Value: expected.val}))
			} else {
				Expect(envs).To(ContainElement(corev1.EnvVar{
					Name: expected.name,
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: expected.secretName},
							Key:                  expected.secretKey,
						}},
				}))
			}
		}

	})
	It("should render with Syslog configuration", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		var ps int32 = 180
		instance.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Syslog: &operatorv1.SyslogStoreSpec{
				Endpoint:   "tcp://1.2.3.4:80",
				PacketSize: &ps,
				LogTypes: []operatorv1.SyslogLogType{
					operatorv1.SyslogLogDNS,
					operatorv1.SyslogLogFlows,
					operatorv1.SyslogLogIDSEvents,
				},
			},
		}
		component := render.Fluentd(instance, nil, esConfigMap, s3Creds, splkCreds, filters, eksConfig, nil, installation)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Spec.Volumes).To(HaveLen(2))
		envs := ds.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []struct {
			name       string
			val        string
			secretName string
			secretKey  string
		}{
			{"SYSLOG_HOST", "1.2.3.4", "", ""},
			{"SYSLOG_PORT", "80", "", ""},
			{"SYSLOG_PROTOCOL", "tcp", "", ""},
			{"SYSLOG_FLUSH_INTERVAL", "5s", "", ""},
			{"SYSLOG_PACKET_SIZE", "180", "", ""},
			{"SYSLOG_DNS_LOG", "true", "", ""},
			{"SYSLOG_FLOW_LOG", "true", "", ""},
			{"SYSLOG_IDS_EVENT_LOG", "true", "", ""},
		}
		for _, expected := range expectedEnvs {
			if expected.val != "" {
				Expect(envs).To(ContainElement(corev1.EnvVar{Name: expected.name, Value: expected.val}))
			} else {
				Expect(envs).To(ContainElement(corev1.EnvVar{
					Name: expected.name,
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: expected.secretName},
							Key:                  expected.secretKey,
						}},
				}))
			}
		}
		Expect(envs).To(ContainElement(corev1.EnvVar{
			Name: "SYSLOG_HOSTNAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: "spec.nodeName",
				}},
		}))
	})

	It("should render with splunk configuration with ca", func() {
		splkCreds := &render.SplunkCredential{
			Token:       []byte("TokenForHEC"),
			Certificate: []byte("Certificates"),
		}
		instance.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Splunk: &operatorv1.SplunkStoreSpec{
				Endpoint: "https://1.2.3.4:8088",
			},
		}

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "logcollector-splunk-credentials", ns: "tigera-fluentd", group: "", version: "v1", kind: "Secret"},
			{name: "logcollector-splunk-public-certificate", ns: "tigera-fluentd", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// Should render the correct resources.
		component := render.Fluentd(instance, nil, esConfigMap, s3Creds, splkCreds, filters, eksConfig, nil, installation)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Spec.Volumes).To(HaveLen(3))

		var volnames []string
		for _, vol := range ds.Spec.Template.Spec.Volumes {
			volnames = append(volnames, vol.Name)
		}
		Expect(volnames).To(ContainElement("splunk-certificates"))

		envs := ds.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []struct {
			name       string
			val        string
			secretName string
			secretKey  string
		}{
			{"SPLUNK_FLOW_LOG", "true", "", ""},
			{"SPLUNK_AUDIT_LOG", "true", "", ""},
			{"SPLUNK_DNS_LOG", "true", "", ""},
			{"SPLUNK_HEC_HOST", "1.2.3.4", "", ""},
			{"SPLUNK_HEC_PORT", "8088", "", ""},
			{"SPLUNK_PROTOCOL", "https", "", ""},
			{"SPLUNK_FLUSH_INTERVAL", "5s", "", ""},
			{"SPLUNK_HEC_TOKEN", "", "logcollector-splunk-credentials", "token"},
			{"SPLUNK_CA_FILE", "/etc/ssl/splunk/ca.pem", "", ""},
		}
		for _, expected := range expectedEnvs {
			if expected.val != "" {
				Expect(envs).To(ContainElement(corev1.EnvVar{Name: expected.name, Value: expected.val}))
			} else {
				Expect(envs).To(ContainElement(corev1.EnvVar{
					Name: expected.name,
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: expected.secretName},
							Key:                  expected.secretKey,
						}},
				}))
			}
		}
	})

	It("should render with splunk configuration without ca", func() {
		splkCreds := &render.SplunkCredential{
			Token: []byte("TokenForHEC"),
		}
		instance.Spec.AdditionalStores = &operatorv1.AdditionalLogStoreSpec{
			Splunk: &operatorv1.SplunkStoreSpec{
				Endpoint: "https://1.2.3.4:8088",
			},
		}

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "logcollector-splunk-credentials", ns: "tigera-fluentd", group: "", version: "v1", kind: "Secret"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// Should render the correct resources.
		component := render.Fluentd(instance, nil, esConfigMap, s3Creds, splkCreds, filters, eksConfig, nil, installation)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		envs := ds.Spec.Template.Spec.Containers[0].Env

		expectedEnvs := []struct {
			name       string
			val        string
			secretName string
			secretKey  string
		}{
			{"SPLUNK_FLOW_LOG", "true", "", ""},
			{"SPLUNK_AUDIT_LOG", "true", "", ""},
			{"SPLUNK_DNS_LOG", "true", "", ""},
			{"SPLUNK_HEC_HOST", "1.2.3.4", "", ""},
			{"SPLUNK_HEC_PORT", "8088", "", ""},
			{"SPLUNK_PROTOCOL", "https", "", ""},
			{"SPLUNK_FLUSH_INTERVAL", "5s", "", ""},
			{"SPLUNK_HEC_TOKEN", "", "logcollector-splunk-credentials", "token"},
		}

		Expect(envs).NotTo(ContainElement(corev1.EnvVar{Name: "SPLUNK_CA_FILE", Value: "/etc/ssl/splunk/ca.pem"}))
		for _, expected := range expectedEnvs {
			if expected.val != "" {
				Expect(envs).To(ContainElement(corev1.EnvVar{Name: expected.name, Value: expected.val}))
			} else {
				Expect(envs).To(ContainElement(corev1.EnvVar{
					Name: expected.name,
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: expected.secretName},
							Key:                  expected.secretKey,
						}},
				}))
			}
		}
	})

	It("should render with filter", func() {
		filters = &render.FluentdFilters{
			Flow: "flow-filter",
		}

		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "fluentd-filters", ns: "tigera-fluentd", group: "", version: "v1", kind: "ConfigMap"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		// Should render the correct resources.
		component := render.Fluentd(instance, nil, esConfigMap, s3Creds, splkCreds, filters, eksConfig, nil, installation)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		ds := GetResource(resources, "fluentd-node", "tigera-fluentd", "apps", "v1", "DaemonSet").(*apps.DaemonSet)
		Expect(ds.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(ds.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/fluentd-filters"))
		envs := ds.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "FLUENTD_FLOW_FILTERS", Value: "true"}))
		Expect(envs).ToNot(ContainElement(corev1.EnvVar{Name: "FLUENTD_DNS_FILTERS", Value: "true"}))
	})

	It("should render with EKS Cloudwatch Log", func() {
		expectedResources := []struct {
			name    string
			ns      string
			group   string
			version string
			kind    string
		}{
			{name: "tigera-fluentd", ns: "", group: "", version: "v1", kind: "Namespace"},
			{name: "eks-log-forwarder", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "eks-log-forwarder", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "eks-log-forwarder", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "eks-log-forwarder", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			{name: "tigera-eks-log-forwarder-secret", ns: "tigera-fluentd", group: "", version: "v1", kind: "Secret"},
			{name: "eks-log-forwarder", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "Deployment"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRole"},
			{name: "tigera-fluentd", ns: "", group: "rbac.authorization.k8s.io", version: "v1", kind: "ClusterRoleBinding"},
			{name: "tigera-fluentd", ns: "", group: "policy", version: "v1beta1", kind: "PodSecurityPolicy"},
			{name: "fluentd-node", ns: "tigera-fluentd", group: "", version: "v1", kind: "ServiceAccount"},
			// Daemonset
			{name: "fluentd-node", ns: "tigera-fluentd", group: "apps", version: "v1", kind: "DaemonSet"},
		}

		fetchInterval := int32(900)
		eksConfig = &render.EksCloudwatchLogConfig{
			AwsId:         []byte("aws-id"),
			AwsKey:        []byte("aws-key"),
			AwsRegion:     "us-west-1",
			GroupName:     "dummy-eks-cluster-cloudwatch-log-group",
			FetchInterval: fetchInterval,
		}
		installation = &operatorv1.InstallationSpec{
			KubernetesProvider: operatorv1.ProviderEKS,
		}
		component := render.Fluentd(instance, nil, esConfigMap, s3Creds, splkCreds, filters, eksConfig, nil, installation)
		resources, _ := component.Objects()
		Expect(len(resources)).To(Equal(len(expectedResources)))

		// Should render the correct resources.
		i := 0
		for _, expectedRes := range expectedResources {
			ExpectResource(resources[i], expectedRes.name, expectedRes.ns, expectedRes.group, expectedRes.version, expectedRes.kind)
			i++
		}

		deploy := GetResource(resources, "eks-log-forwarder", "tigera-fluentd", "apps", "v1", "Deployment").(*apps.Deployment)
		Expect(deploy.Spec.Template.Spec.InitContainers).To(HaveLen(1))
		Expect(deploy.Spec.Template.Spec.Containers).To(HaveLen(1))
		Expect(deploy.Spec.Template.Annotations).To(HaveKey("hash.operator.tigera.io/eks-cloudwatch-log-credentials"))
		envs := deploy.Spec.Template.Spec.Containers[0].Env
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "K8S_PLATFORM", Value: "eks"}))
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "AWS_REGION", Value: eksConfig.AwsRegion}))
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "ELASTIC_HOST", Value: "tigera-secure-es-http.tigera-elasticsearch.svc"}))

		fetchIntervalVal := "900"
		Expect(envs).To(ContainElement(corev1.EnvVar{Name: "EKS_CLOUDWATCH_LOG_FETCH_INTERVAL", Value: fetchIntervalVal}))
	})
})
