// Copyright (c) 2023 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package csr

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/monitor"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("CSR controller tests", func() {
	var (
		cli                client.Client
		ctx                context.Context
		r                  reconcileCSR
		scheme             *runtime.Scheme
		mockStatus         *status.MockStatus
		installation       *operatorv1.Installation
		certificateManager certificatemanager.CertificateManager
		err                error
	)

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(certificatesv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(rbacv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		// Create a client that will have a crud interface of k8s objects.
		cli = fake.NewClientBuilder().WithScheme(scheme).Build()
		ctx = context.Background()
		installation = &operatorv1.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operatorv1.InstallationSpec{
				Variant:  operatorv1.TigeraSecureEnterprise,
				Registry: "some.registry.org/",
			},
		}
		Expect(cli.Create(ctx, installation)).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, &operatorv1.Monitor{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Spec:       operatorv1.MonitorSpec{ExternalPrometheus: &operatorv1.ExternalPrometheus{Namespace: "default"}},
		})).NotTo(HaveOccurred())
		certificateManager, err = certificatemanager.Create(cli, &installation.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		mockStatus = &status.MockStatus{}
		mockStatus.On("OnCRFound").Return()
		r = reconcileCSR{
			client:              cli,
			scheme:              scheme,
			provider:            operatorv1.ProviderNone,
			clusterDomain:       dns.DefaultClusterDomain,
			allowedTLSAssets:    allowedAssets(dns.DefaultClusterDomain),
			enterpriseCRDExists: true,
		}
	})

	Context("csr reconciliation", func() {
		It("should reconcile the CSR controller", func() {
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should reconcile a submitted CSR", func() {
			Expect(cli.Create(ctx, validPod())).NotTo(HaveOccurred())
			csr := validCSR(validX509CR(), validPod())
			Expect(cli.Create(ctx, csr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(r.client.Get(ctx, client.ObjectKey{Name: csr.Name}, csr)).NotTo(HaveOccurred())
			Expect(csr.Status.Conditions).To(HaveLen(1))
			Expect(csr.Status.Conditions[0].Type).To(Equal(certificatesv1.CertificateApproved))
			Expect(csr.Status.Conditions[0].Status).To(Equal(corev1.ConditionTrue))
			Expect(csr.Status.Certificate).ToNot(BeEmpty())
			Expect(cli.Get(ctx, types.NamespacedName{Name: certificatemanagement.CSRClusterRoleName}, &rbacv1.ClusterRole{})).NotTo(HaveOccurred())
		})

		It("should reconcile 2 submitted CSRs", func() {
			validPod2 := validPod()
			validPod2.Name = validPod2.Name + "2"
			Expect(cli.Create(ctx, validPod2)).NotTo(HaveOccurred())
			csr2 := validCSR(validX509CR(), validPod2)
			csr2.Name = csr2.Name + "2"
			Expect(cli.Create(ctx, csr2)).NotTo(HaveOccurred())

			Expect(cli.Create(ctx, validPod())).NotTo(HaveOccurred())
			csr := validCSR(validX509CR(), validPod())
			Expect(cli.Create(ctx, csr)).NotTo(HaveOccurred())

			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())

			Expect(r.client.Get(ctx, client.ObjectKey{Name: csr.Name}, csr)).NotTo(HaveOccurred())
			Expect(csr.Status.Conditions).To(HaveLen(1))
			Expect(csr.Status.Conditions[0].Type).To(Equal(certificatesv1.CertificateApproved))
			Expect(csr.Status.Conditions[0].Status).To(Equal(corev1.ConditionTrue))
			Expect(csr.Status.Certificate).ToNot(BeEmpty())

			Expect(r.client.Get(ctx, client.ObjectKey{Name: csr2.Name}, csr2)).NotTo(HaveOccurred())
			Expect(csr2.Status.Conditions).To(HaveLen(1))
			Expect(csr2.Status.Conditions[0].Type).To(Equal(certificatesv1.CertificateApproved))
			Expect(csr2.Status.Conditions[0].Status).To(Equal(corev1.ConditionTrue))
			Expect(csr2.Status.Certificate).ToNot(BeEmpty())
		})

		It("should reject a submitted CSR that does not pass validation", func() {
			csr := validCSR(validX509CR(), validPod())
			csr.Spec.Username = "attacker"
			Expect(cli.Create(ctx, csr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(r.client.Get(ctx, client.ObjectKey{Name: csr.Name}, csr)).NotTo(HaveOccurred())
			Expect(csr.Status.Conditions).To(HaveLen(1))
			Expect(csr.Status.Conditions[0].Type).To(Equal(certificatesv1.CertificateDenied))
			Expect(csr.Status.Conditions[0].Status).To(Equal(corev1.ConditionTrue))
			Expect(csr.Status.Certificate).To(BeEmpty())
		})
	})

	table.DescribeTable("csr validation", func(csr *certificatesv1.CertificateSigningRequest, pod *corev1.Pod, expectError, expectRelevant bool) {
		certificate, err := r.validate(csr, pod)
		if expectError {
			Expect(err).To(HaveOccurred())
		} else if expectRelevant {
			Expect(relevantCSR(csr)).To(BeTrue())
			Expect(err).ToNot(HaveOccurred())
			Expect(certificate.ExtKeyUsage).To(Equal(extKeyUsage))
			Expect(certificate.DNSNames).To(Equal(monitor.PrometheusTLSServerDNSNames(dns.DefaultClusterDomain)))
			Expect(certificate.Subject.CommonName).To(Equal(monitor.PrometheusTLSServerDNSNames(dns.DefaultClusterDomain)[0]))
			Expect(certificate.IPAddresses).To(Equal([]net.IP{net.ParseIP(pod.Status.PodIP).To4()}))
			Expect(certificate.IsCA).To(BeFalse())
		} else {
			Expect(relevantCSR(csr)).To(BeFalse())
		}
	},
		table.Entry("valid CSR / happy flow", validCSR(validX509CR(), validPod()), validPod(), false, true),
		table.Entry("valid CSR / no pod", validCSR(validX509CR(), validPod()), nil, true, true),
		table.Entry("unrecognized csr name", invalidCSR(validX509CR(), validPod(), invalidName), validPod(), true, true),
		table.Entry("invalid username", invalidCSR(validX509CR(), validPod(), invalidUserName), validPod(), true, true),
		table.Entry("invalid certificate request", invalidCSR(validX509CR(), validPod(), invalidRequest), validPod(), true, true),
		table.Entry("previously denied csr", invalidCSR(validX509CR(), validPod(), invalidDenied), validPod(), false, false),
		table.Entry("previously failed csr", invalidCSR(validX509CR(), validPod(), invalidFailed), validPod(), false, false),
		table.Entry("bad DNS names in x509 certificate request", invalidCSR(invalidX509CR(invalidDNSNames), validPod()), validPod(), true, true),
		table.Entry("bad CN in x509 certificate request", invalidCSR(invalidX509CR(invalidCN), validPod()), validPod(), true, true),
		table.Entry("bad IP in x509 certificate request", invalidCSR(invalidX509CR(invalidIP), validPod()), validPod(), true, true),
		table.Entry("irrelevant signer name", invalidCSR(invalidX509CR(), validPod(), invalidSignername), validPod(), false, false),
	)

	table.DescribeTable("getPod", func(csr *certificatesv1.CertificateSigningRequest, pod *corev1.Pod, expectPodNil bool) {
		if pod != nil {
			Expect(cli.Create(ctx, pod)).NotTo(HaveOccurred())
		}
		foundPod, err := r.getPod(ctx, csr)
		Expect(err).NotTo(HaveOccurred())
		if expectPodNil {
			Expect(foundPod).To(BeNil())
		} else {
			Expect(foundPod).NotTo(BeNil())
		}
	},
		table.Entry("Valid CSR, pod found", validCSR(validX509CR(), validPod()), validPod(), false),
		table.Entry("Valid CSR, no pod found", validCSR(validX509CR(), validPod()), nil, true),
		table.Entry("Valid CSR, no matching pod found due to different uid", validCSR(validX509CR(), validPod()), invalidPod(invalidUID), true),
		table.Entry("Valid CSR, no matching pod found due to different pod name", validCSR(validX509CR(), validPod()), invalidPod(invalidName), true),
		table.Entry("Valid CSR, no matching pod found due to different csr username", invalidCSR(validX509CR(), validPod(), invalidUserName), validPod(), true),
		table.Entry("Invalid CSR, irrelevant pod names", invalidCSR(invalidX509CR(), validPod(), invalidExtraPodNames), validPod(), true),
		table.Entry("Invalid CSR, irrelevant pod names len", invalidCSR(invalidX509CR(), validPod(), invalidExtraPodNamesLen), validPod(), true),
		table.Entry("Invalid CSR, irrelevant pod UIDs", invalidCSR(invalidX509CR(), validPod(), invalidExtraPodUIDs), validPod(), true),
		table.Entry("Invalid CSR, irrelevant pod UIDs len", invalidCSR(invalidX509CR(), validPod(), invalidExtraPodUIDsLen), validPod(), true),
	)
})

func validX509CR() *x509.CertificateRequest {
	subj := pkix.Name{
		CommonName: "prometheus-http-api",
	}
	extKeyUsages := []asn1.ObjectIdentifier{
		// ExtKeyUsageServerAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 1},
		// ExtKeyUsageClientAuth
		{1, 3, 6, 1, 5, 5, 7, 3, 2},
	}

	extKeyUsagesVal, err := asn1.Marshal(extKeyUsages)
	Expect(err).NotTo(HaveOccurred())
	return &x509.CertificateRequest{
		Subject:            subj,
		DNSNames:           []string{"prometheus-http-api", "prometheus-http-api.tigera-prometheus", "prometheus-http-api.tigera-prometheus.svc", "prometheus-http-api.tigera-prometheus.svc.cluster.local"},
		IPAddresses:        []net.IP{net.ParseIP("1.2.3.4")},
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 37},
				Value: extKeyUsagesVal,
			},
		},
	}
}
func validCSR(cr *x509.CertificateRequest, pod *corev1.Pod) *certificatesv1.CertificateSigningRequest {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	buf := bytes.NewBuffer([]byte{})
	err = pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	Expect(err).NotTo(HaveOccurred())
	certificateRequest, err := x509.CreateCertificateRequest(rand.Reader, cr, key)
	Expect(err).NotTo(HaveOccurred())
	csr := &certificatesv1.CertificateSigningRequest{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CertificateSigningRequest",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "calico-node-prometheus-tls:prometheus-calico-node-prometheus-0",
			Labels: map[string]string{
				"k8s-app":                "tigera-prometheus",
				"operator.tigera.io/csr": "tigera-prometheus",
			},
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request: pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE REQUEST", Bytes: certificateRequest,
			}),
			SignerName: "tigera.io/operator-signer",
			Username:   "system:serviceaccount:tigera-prometheus:prometheus",
			Extra: map[string]certificatesv1.ExtraValue{
				"authentication.kubernetes.io/pod-name": []string{pod.Name},
				"authentication.kubernetes.io/pod-uid":  []string{string(pod.UID)},
			},
		},
		Status: certificatesv1.CertificateSigningRequestStatus{},
	}

	return csr
}

type invalidation int

func validPod() *corev1.Pod {
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "prometheus-calico-node-prometheus-0",
			Namespace: "tigera-prometheus",
			Labels: map[string]string{
				"k8s-app": "tigera-prometheus",
			},
			UID: "uid",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "prometheus",
		},
		Status: corev1.PodStatus{
			PodIP: "1.2.3.4",
		},
	}
}

const (
	invalidUID invalidation = iota
	invalidName
	invalidUserName
	invalidRequest
	invalidDenied
	invalidFailed
	invalidDNSNames
	invalidCN
	invalidIP
	invalidSignername
	invalidExtraPodNames
	invalidExtraPodNamesLen
	invalidExtraPodUIDs
	invalidExtraPodUIDsLen
)

func invalidCSR(cr *x509.CertificateRequest, pod *corev1.Pod, invalidations ...invalidation) *certificatesv1.CertificateSigningRequest {
	csr := validCSR(cr, pod)
	for _, i := range invalidations {
		switch i {
		case invalidUserName:
			csr.Spec.Username = "invalid"
		case invalidName:
			csr.Name = "invalid"
		case invalidRequest:
			csr.Spec.Request = []byte("invalid")
		case invalidDenied:
			csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateDenied,
					Status: corev1.ConditionTrue,
				},
			}
		case invalidFailed:
			csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateFailed,
					Status: corev1.ConditionTrue,
				},
			}
		case invalidSignername:
			csr.Spec.SignerName = "not.relevant/signerName"
		case invalidExtraPodNames:
			csr.Spec.Extra["authentication.kubernetes.io/pod-name"] = []string{"a"}
		case invalidExtraPodNamesLen:
			csr.Spec.Extra["authentication.kubernetes.io/pod-name"] = []string{"prometheus-calico-node-prometheus-0", "b"}
		case invalidExtraPodUIDs:
			csr.Spec.Extra["authentication.kubernetes.io/pod-uid"] = []string{"a"}
		case invalidExtraPodUIDsLen:
			csr.Spec.Extra["authentication.kubernetes.io/pod-uid"] = []string{"uid", "b"}
		}
	}
	return csr
}

func invalidPod(invalidations ...invalidation) *corev1.Pod {
	pod := validPod()

	for _, i := range invalidations {
		switch i {
		case invalidUID:
			pod.UID = "invalid"
		case invalidName:
			pod.Name = "invalid"
		}
	}
	return pod
}

func invalidX509CR(invalidations ...invalidation) *x509.CertificateRequest {
	cr := validX509CR()
	for _, i := range invalidations {
		switch i {
		case invalidDNSNames:
			cr.DNSNames = []string{"google.com"}
		case invalidCN:
			cr.Subject.CommonName = "google.com"
		case invalidIP:
			cr.IPAddresses = []net.IP{net.ParseIP("8.8.8.8")}
		}
	}
	return cr

}
