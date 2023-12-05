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
	"fmt"
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
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("CSR controller tests", func() {
	var (
		cli                client.Client
		ctx                context.Context
		r                  ReconcileCSR
		scheme             *runtime.Scheme
		mockStatus         *status.MockStatus
		installation       *operatorv1.Installation
		certificateManager certificatemanager.CertificateManager
		err                error
		validPod           *corev1.Pod
	)

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(certificatesv1.AddToScheme(scheme)).NotTo(HaveOccurred())
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
		certificateManager, err = certificatemanager.Create(cli, &installation.Spec, dns.DefaultClusterDomain, common.OperatorNamespace(), certificatemanager.AllowCACreation())
		Expect(err).NotTo(HaveOccurred())
		Expect(cli.Create(ctx, certificateManager.KeyPair().Secret(common.OperatorNamespace()))).NotTo(HaveOccurred())
		mockStatus = &status.MockStatus{}
		mockStatus.On("OnCRFound").Return()
		r = ReconcileCSR{
			client:           cli,
			scheme:           scheme,
			provider:         operatorv1.ProviderNone,
			clusterDomain:    dns.DefaultClusterDomain,
			allowedTLSAssets: allowedAssets(dns.DefaultClusterDomain),
		}
		// Create the valid pod that is requesting a CSR.
		validPod = &corev1.Pod{
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
	})

	Context("csr reconciliation", func() {
		It("should reconcile the CSR controller", func() {
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
		})

		It("should reconcile a submitted CSR", func() {
			Expect(cli.Create(ctx, validPod)).NotTo(HaveOccurred())
			csr := newCSR(newX509CertificateRequest(), validPod)
			Expect(cli.Create(ctx, csr)).NotTo(HaveOccurred())
			_, err = r.Reconcile(ctx, reconcile.Request{})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(r.client.Get(ctx, client.ObjectKey{Name: csr.Name}, csr)).NotTo(HaveOccurred())
			Expect(csr.Status.Conditions).To(HaveLen(1))
			Expect(csr.Status.Conditions[0].Type).To(Equal(certificatesv1.CertificateApproved))
			Expect(csr.Status.Conditions[0].Status).To(Equal(corev1.ConditionTrue))
			Expect(csr.Status.Certificate).ToNot(BeEmpty())
		})

		It("should reconcile 2 submitted CSRs", func() {
			validPod2 := validPod.DeepCopy()
			validPod2.Name = validPod2.Name + "2"
			Expect(cli.Create(ctx, validPod2)).NotTo(HaveOccurred())
			csr2 := newCSR(newX509CertificateRequest(), validPod2)
			csr2.Name = csr2.Name + "2"
			Expect(cli.Create(ctx, csr2)).NotTo(HaveOccurred())

			Expect(cli.Create(ctx, validPod)).NotTo(HaveOccurred())
			csr := newCSR(newX509CertificateRequest(), validPod)
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
			csr := newCSR(newX509CertificateRequest(), validPod)
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

	table.DescribeTable("csr validation", func(csrfunc func() *certificatesv1.CertificateSigningRequest, expectError bool) {
		csr := csrfunc()
		certificate, err := r.validate(csr, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "prometheus-calico-node-prometheus-0"}, Status: corev1.PodStatus{PodIP: "1.2.3.4"}})
		if expectError {
			Expect(err).To(HaveOccurred())
		} else if relevantCSR(csr) {
			Expect(err).ToNot(HaveOccurred())
			Expect(certificate.ExtKeyUsage).To(Equal(extKeyUsage))
			Expect(certificate.DNSNames).To(Equal(monitor.PrometheusTLSServerDNSNames(dns.DefaultClusterDomain)))
			Expect(certificate.Subject.CommonName).To(Equal(monitor.PrometheusTLSServerDNSNames(dns.DefaultClusterDomain)[0]))
			Expect(certificate.IPAddresses).To(Equal([]net.IP{net.ParseIP("1.2.3.4").To4()}))
			Expect(certificate.IsCA).To(BeFalse())
		}
	},
		table.Entry("valid CSR / happy flow", func() *certificatesv1.CertificateSigningRequest {
			return newCSR(newX509CertificateRequest(), validPod)
		}, false),
		table.Entry("unrecognized csr name", func() *certificatesv1.CertificateSigningRequest {
			csr := newCSR(newX509CertificateRequest(), validPod)
			csr.Name = "fake"
			return csr
		},
			true),
		table.Entry("invalid requestor", func() *certificatesv1.CertificateSigningRequest {
			csr := newCSR(newX509CertificateRequest(), validPod)
			csr.Spec.Username = "fake"
			return csr
		}, true),
		table.Entry("invalid certificate request", func() *certificatesv1.CertificateSigningRequest {
			csr := newCSR(newX509CertificateRequest(), validPod)
			csr.Spec.Request = []byte("fake")
			return csr
		}, true),
		table.Entry("invalid certificate request public key", func() *certificatesv1.CertificateSigningRequest {
			csr := newCSR(newX509CertificateRequest(), validPod)
			csr.Spec.Request = []byte("fake")
			return csr
		}, true),
		table.Entry("previously denied csr", func() *certificatesv1.CertificateSigningRequest {
			csr := newCSR(newX509CertificateRequest(), validPod)
			csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateDenied,
					Status: corev1.ConditionTrue,
				},
			}
			return csr
		}, false),
		table.Entry("previously failed csr", func() *certificatesv1.CertificateSigningRequest {
			csr := newCSR(newX509CertificateRequest(), validPod)
			csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1.CertificateFailed,
					Status: corev1.ConditionTrue,
				},
			}
			return csr
		}, false),
		table.Entry("bad DNS names in x509 certificate request", func() *certificatesv1.CertificateSigningRequest {
			cr := newX509CertificateRequest()
			cr.DNSNames = []string{"google.com"}
			return newCSR(cr, validPod)
		}, true),
		table.Entry("bad CN in x509 certificate request", func() *certificatesv1.CertificateSigningRequest {
			cr := newX509CertificateRequest()
			cr.Subject.CommonName = "google.com"
			return newCSR(cr, validPod)
		}, true),
		table.Entry("bad IP in x509 certificate request", func() *certificatesv1.CertificateSigningRequest {
			cr := newX509CertificateRequest()
			cr.IPAddresses = []net.IP{net.ParseIP("8.8.8.8")}
			return newCSR(cr, validPod)
		}, true),
	)

	table.DescribeTable("getPod", func(preconditions func() *certificatesv1.CertificateSigningRequest, expectPodNil bool) {
		foundPod, err := r.getPod(ctx, preconditions())
		Expect(err).NotTo(HaveOccurred())
		if expectPodNil {
			Expect(foundPod).To(BeNil())
		} else {
			Expect(foundPod).NotTo(BeNil())
		}
	},
		table.Entry("Valid CSR, pod found", func() *certificatesv1.CertificateSigningRequest {
			Expect(cli.Create(ctx, validPod)).NotTo(HaveOccurred())
			return newCSR(newX509CertificateRequest(), validPod)
		}, false),
		table.Entry("Valid CSR, nod pod found", func() *certificatesv1.CertificateSigningRequest {
			return newCSR(newX509CertificateRequest(), validPod)
		}, true),
		table.Entry("Valid CSR, nod match pod found due to different uid", func() *certificatesv1.CertificateSigningRequest {
			Expect(cli.Create(ctx, validPod)).NotTo(HaveOccurred())
			validPod.UID = "nope"
			return newCSR(newX509CertificateRequest(), validPod)
		}, true),
		table.Entry("Valid CSR, nod match pod found due to different pod name", func() *certificatesv1.CertificateSigningRequest {
			csr := newCSR(newX509CertificateRequest(), validPod)
			validPod.Name = "nope"
			Expect(cli.Create(ctx, validPod)).NotTo(HaveOccurred())
			return csr
		}, true),
		table.Entry("Valid CSR, nod match pod found due to different csr username", func() *certificatesv1.CertificateSigningRequest {
			Expect(cli.Create(ctx, validPod)).NotTo(HaveOccurred())
			csr := newCSR(newX509CertificateRequest(), validPod)
			csr.Spec.Username = "nope"
			return csr
		}, true),
	)
})

func newX509CertificateRequest() *x509.CertificateRequest {
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

func newCSR(cr *x509.CertificateRequest, pod *corev1.Pod) *certificatesv1.CertificateSigningRequest {
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
				"authentication.kubernetes.io/pod-uid":  []string{fmt.Sprintf("%s", pod.UID)},
			},
		},
		Status: certificatesv1.CertificateSigningRequestStatus{},
	}

	return csr
}
