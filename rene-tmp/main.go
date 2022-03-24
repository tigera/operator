// Copyright (c) 2022 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/tigera/operator/pkg/render/monitor"

	"github.com/openshift/library-go/pkg/crypto"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/tls"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/yaml"
)

var (
	cd              = "cluster.local"
	managerDNSNames = append(dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, cd), render.ManagerServiceIP)
	nodeDNSNames    = []string{render.FelixCommonName}
	typhaDNSNames   = []string{render.TyphaCommonName}
	complianceNames = dns.GetServiceDNSNames(render.ComplianceServiceName, render.ComplianceNamespace, cd)
	pcapNames       = dns.GetServiceDNSNames(render.PacketCaptureServiceName, render.PacketCaptureNamespace, cd)
	fdNames         = dns.GetServiceDNSNames(render.FluentdPrometheusTLSSecretName, render.LogCollectorNamespace, cd)
	apiNames        = dns.GetServiceDNSNames(render.ProjectCalicoApiServerServiceName(operatorv1.TigeraSecureEnterprise), rmeta.APIServerNamespace(operatorv1.TigeraSecureEnterprise), cd)
	promNames       = dns.GetServiceDNSNames(monitor.PrometheusHTTPAPIServiceName, common.TigeraPrometheusNamespace, cd)
)

func main() {

	cryptoCA, err := tls.MakeCA("rene-ca")
	if err != nil {
		panic(err)
	}

	node := create(cryptoCA, render.NodeTLSSecretName, common.OperatorNamespace(), nodeDNSNames)
	typha := create(cryptoCA, render.TyphaTLSSecretName, common.OperatorNamespace(), typhaDNSNames)
	typhaca := &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "typha-ca", Namespace: common.OperatorNamespace()},
		Data: map[string]string{
			"caBundle": string(typha.Data[corev1.TLSCertKey]),
		}}
	managerInt := create(cryptoCA, render.ManagerTLSSecretName, common.OperatorNamespace(), managerDNSNames)
	compliance := create(cryptoCA, render.ComplianceServerCertSecret, common.OperatorNamespace(), complianceNames)
	pcap := create(cryptoCA, render.PacketCaptureCertSecret, common.OperatorNamespace(), pcapNames)
	api := create(cryptoCA, render.ProjectCalicoApiServerTLSSecretName(operatorv1.TigeraSecureEnterprise), common.OperatorNamespace(), apiNames)

	fluentd := create(cryptoCA, render.FluentdPrometheusTLSSecretName, common.OperatorNamespace(), apiNames)
	prom := create(cryptoCA, monitor.PrometheusTLSSecretName, common.OperatorNamespace(), apiNames)
	fluentdca := &corev1.ConfigMap{TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "typha-ca", Namespace: common.OperatorNamespace()},
		Data: map[string]string{
			"ca.crt": string(fluentd.Data[corev1.TLSCertKey]),
		}}

	modKey(managerInt, corev1.TLSCertKey, "cert")
	modKey(managerInt, corev1.TLSPrivateKeyKey, "key")
	modKey(node, corev1.TLSCertKey, "cert.crt")
	modKey(node, corev1.TLSPrivateKeyKey, "key.key")
	node.Data["common-name"] = []byte(render.FelixCommonName)
	modKey(typha, corev1.TLSCertKey, "cert.crt")
	modKey(typha, corev1.TLSPrivateKeyKey, "key.key")
	typha.Data["common-name"] = []byte(render.TyphaCommonName)

	yamls := []metav1.Object{
		node,
		typha,
		managerInt,
		typhaca,
		compliance,
		pcap,
		api,
		fluentd,
		fluentdca,
		prom,
	}

	for _, s := range yamls {
		b, err := yaml.Marshal(s)
		if err != nil {
			panic(err)
		}
		err = ioutil.WriteFile(fmt.Sprintf("rene-tmp/%s.yaml", s.GetName()), b, 0777)
		if err != nil {
			panic(err)
		}
	}

}

func modKey(secret *corev1.Secret, from, to string) {
	secret.Data[to] = secret.Data[from]
	delete(secret.Data, from)
}

func create(ca *crypto.CA, secretName, secretNamespace string, dnsNames []string) *corev1.Secret {
	tlsCfg, err := ca.MakeServerCertForDuration(sets.NewString(dnsNames...), rmeta.DefaultCertificateDuration, tls.SetServerAuth, tls.SetClientAuth)
	if err != nil {
		panic(err)
	}
	secret, err := getSecretFromTLSConfig(tlsCfg, secretName, secretNamespace)
	secret.APIVersion = "v1"
	if err != nil {
		panic(err)
	}
	return secret
}

func getSecretFromTLSConfig(
	tls *crypto.TLSCertificateConfig, secretName, secretNamespace string) (*corev1.Secret, error) {
	keyContent, crtContent := &bytes.Buffer{}, &bytes.Buffer{}
	if err := tls.WriteCertConfig(crtContent, keyContent); err != nil {
		return nil, err
	}

	data := make(map[string][]byte)
	data[corev1.TLSPrivateKeyKey] = keyContent.Bytes()
	data[corev1.TLSCertKey] = crtContent.Bytes()
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: secretNamespace,
		},
		Data: data,
	}, nil
}
