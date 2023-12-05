package csr

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/monitor"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/utils"
	rmonitor "github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	typedcertificatesv1 "k8s.io/client-go/kubernetes/typed/certificates/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var log = logf.Log.WithName("controller_csr")
var controllerName = "csr-controller"

// LabelName label that we set on our CSRs, this helps us exclude irrelevant CSRs.
const LabelName = "operator.tigera.io/csr"

var extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

// relevantCSR returns true if a csr is relevant to this controller.
func relevantCSR(csr *certificatesv1.CertificateSigningRequest) bool {
	if _, found := csr.Labels[LabelName]; !found {
		return false
	}
	for _, condition := range csr.Status.Conditions {
		if (condition.Type == certificatesv1.CertificateDenied || condition.Type == certificatesv1.CertificateFailed) && condition.Status == corev1.ConditionTrue {
			// These request statuses are deterministic/non-recoverable.
			return false
		}
	}
	// We are only interested in CSRs that have not been signed. This also excludes
	// us from watching our own updates and reconciling for no reason.
	return csr.Status.Certificate == nil
}

// Add creates a new CSR Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller (currently).
		return nil
	}
	reconciler, err := newReconciler(mgr, opts)
	if err != nil {
		return err
	}

	ctrl, err := controller.New(controllerName, mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return err
	}

	return utils.AddCSRWatchWithRelevancyFn(ctrl, relevantCSR)
}

type tlsAsset struct {
	serviceaccountName      string
	serviceaccountNamespace string
	validDNSNames           []string
}

func newReconciler(mgr manager.Manager, opts options.AddOptions) (reconcile.Reconciler, error) {
	// We need to construct a certificatesV1 client, as this API has methods we rely upon that are not present in the generic client.
	clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return nil, err
	}

	r := &ReconcileCSR{
		client:             mgr.GetClient(),
		scheme:             mgr.GetScheme(),
		provider:           opts.DetectedProvider,
		clusterDomain:      opts.ClusterDomain,
		certificatesClient: clientset.CertificatesV1(),
		allowedTLSAssets:   allowedAssets(opts.ClusterDomain),
	}
	return r, nil
}

// allowedAssets To prevent any abuse of this controller for obtaining a fraudulent certificate, this controller
// will only approve a pre-defined list of assets, based on their 'requestor', dns names and namespaces.
// Some of the information a CSR will contain:
//   - Name: The name is based on the secret name + a pod suffix. We use the secret name as the key to index the map.
//   - Requestor: this is the user identity tied to the request. This will be matched against the sa + namespace.
//   - DNS names: these will be checked against pre-defined dns names for that specific secret name.
//
// The combination of this information (among other checks) will help us reject/approve requests.
func allowedAssets(clusterDomain string) map[string]tlsAsset {
	return map[string]tlsAsset{
		rmonitor.PrometheusServerTLSSecretName: {
			rmonitor.PrometheusServiceAccountName,
			rmonitor.TigeraPrometheusObjectName,
			monitor.PrometheusTLSServerDNSNames(clusterDomain),
		},
	}
}

// blank assignment to verify that ReconcileCompliance implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileCSR{}

// ReconcileCSR Components created by the operator may submit certificate signing requests against k8s under certain
// conditions for signer name "tigera.io/operator-signer". This is the controller that monitors, approves and signs
// these CSRs. It will only sign requests that are pre-defined and reject others in order to avoid malicious requests.
type ReconcileCSR struct {
	client             client.Client
	scheme             *runtime.Scheme
	provider           operatorv1.Provider
	clusterDomain      string
	certificatesClient typedcertificatesv1.CertificatesV1Interface
	allowedTLSAssets   map[string]tlsAsset
}

func (r ReconcileCSR) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling CSR Controller")
	csrList := &certificatesv1.CertificateSigningRequestList{}

	// Filter out unnecessary CSRs. (Calico CSRs are guaranteed to have this label).
	requirement, err := labels.NewRequirement(LabelName, selection.Exists, []string{})
	if err != nil {
		return reconcile.Result{}, err
	}
	if err := r.client.List(ctx, csrList, &client.ListOptions{LabelSelector: labels.NewSelector().Add(*requirement)}); err != nil {
		return reconcile.Result{}, err
	}

	instance := &operatorv1.Installation{}
	if err := r.client.Get(ctx, utils.DefaultInstanceKey, instance); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	certificateManager, err := certificatemanager.Create(r.client, &instance.Spec, r.clusterDomain, common.OperatorNamespace(), certificatemanager.WithLogger(reqLogger))
	if err != nil {
		return reconcile.Result{}, err
	}

	for _, csr := range csrList.Items {
		if csr.Spec.SignerName != utils.OperatorCSRSignerName || csr.Status.Certificate != nil || !relevantCSR(&csr) {
			// Not for us, or already signed.
			continue
		}
		reqLogger.Info("Inspecting CSR with name : %v.", csr.Name)
		pod, err := r.getPod(ctx, &csr)
		if err != nil {
			return reconcile.Result{}, err
		}
		certificateTemplate, err := r.validate(&csr, pod)
		if err != nil {
			csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{
				{
					Type:    certificatesv1.CertificateDenied,
					Message: err.Error(),
					Reason:  err.Error(),
					Status:  corev1.ConditionTrue,
				},
			}
			reqLogger.Error(err, "Rejecting the CSR.")
			_, err = r.certificatesClient.CertificateSigningRequests().UpdateStatus(ctx, &csr, metav1.UpdateOptions{})
			if err != nil {
				return reconcile.Result{}, err
			}
			continue
		}
		csr.Status.Conditions = []certificatesv1.CertificateSigningRequestCondition{
			{
				Type:    certificatesv1.CertificateApproved,
				Message: "Approved",
				Reason:  "Approved",
				Status:  corev1.ConditionTrue,
			},
		}
		reqs := r.certificatesClient.CertificateSigningRequests()
		updatedCSR, err := reqs.UpdateApproval(ctx, csr.Name, &csr, metav1.UpdateOptions{})
		if err != nil {
			return reconcile.Result{}, err
		}
		reqLogger.Info("Approved CSR with name : %v.", csr.Name)

		certificatePEM, err := certificateManager.SignCertificate(certificateTemplate)
		if err != nil {
			reqLogger.Error(err, "error signing certificate request")
			return reconcile.Result{}, err
		}
		updatedCSR.Status.Certificate = certificatePEM

		_, err = r.certificatesClient.CertificateSigningRequests().UpdateStatus(ctx, updatedCSR, metav1.UpdateOptions{})
		if err != nil {
			return reconcile.Result{}, err
		}
		reqLogger.Info("Signed CSR with name : %v.", csr.Name)
	}

	return reconcile.Result{}, nil
}

// validate Criteria include:
// - Verify that the x509 request can be parsed and contains one request block.
// - Verify that the request name matches the deterministic name format that we expect. (More for practical reasons, than for security reasons.)
// - Verify that the service account is allowed to request the common name and/or SANs.
// - Verify that the issuer of the CSR (the pod) indeed is the pod that belongs to the IP in the CSR.
// - Verify that the CSR was not previously denied or failed.
// - Verify that the public key matches the signature on the CSR for the provider algorithm.
// - Key usages are fixed, so the CSR won't be able to affect these settings.
func (r ReconcileCSR) validate(csr *certificatesv1.CertificateSigningRequest, pod *corev1.Pod) (*x509.Certificate, error) {
	firstBlock, restBlocks := pem.Decode(csr.Spec.Request)
	if firstBlock == nil {
		return nil, fmt.Errorf("cannot parse certificate request for CSR with name %s", csr.Name)
	}
	if len(restBlocks) != 0 {
		return nil, fmt.Errorf("unexpected (multiple) pem blocks for CSR with name %s", csr.Name)
	}

	certificateRequest, err := x509.ParseCertificateRequest(firstBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if err = certificateRequest.CheckSignature(); err != nil {
		return nil, err
	}

	// The CSRName is formatted as "<secretName>:<podName>".
	secretName := strings.Split(csr.Name, ":")[0]

	// Validate whether this is a CSR we monitor at all.
	asset, ok := r.allowedTLSAssets[secretName]
	if !ok {
		return nil, fmt.Errorf("this controller is not configured to sign secretName: %s", secretName)
	}

	// Validate whether the requestor of the CSR is registered for the given CSR
	if fmt.Sprintf("system:serviceaccount:%s:%s", asset.serviceaccountNamespace, asset.serviceaccountName) != csr.Spec.Username {
		return nil, fmt.Errorf("invalid requestor %s for CSR with name %s", csr.Spec.Username, csr.Name)
	}

	// Validate whether the DNS names are permitted for the request.
	for _, name := range append(certificateRequest.DNSNames, certificateRequest.Subject.CommonName) {
		var found bool
		for _, valid := range asset.validDNSNames {
			if valid == name {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("invalid dns name \"%s\" found in CSR with name %s", name, csr.Name)
		}
	}

	if len(certificateRequest.IPAddresses) == 1 {
		if pod == nil {
			return nil, fmt.Errorf("pod IP in CSR, but no matching pod can be found for CSR with name %s", csr.Name)
		}
		if pod.Status.PodIP != certificateRequest.IPAddresses[0].String() {
			return nil, fmt.Errorf("invalid pod IP for CSR with name %s", csr.Name)
		}
	} else if len(certificateRequest.IPAddresses) > 1 {
		return nil, fmt.Errorf("unable to request more than 1 IP for CSR with name %s", csr.Name)
	}

	bigint, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	certTemplate := &x509.Certificate{
		// We don't rely on any other part of the subject. Common name is validated already.
		Subject:            pkix.Name{CommonName: certificateRequest.Subject.CommonName},
		SerialNumber:       bigint,
		Version:            3,
		PublicKeyAlgorithm: certificateRequest.PublicKeyAlgorithm,
		PublicKey:          certificateRequest.PublicKey,
		NotBefore:          time.Now(),
		// We currently don't implement the Duration for certificate requests.
		NotAfter: time.Now().Add(tls.DefaultCertificateDuration),
		// For the time being we simply issue the standard usages. There are very few, if any, exceptions in our product.
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: extKeyUsage,
		DNSNames:    certificateRequest.DNSNames,
		IPAddresses: certificateRequest.IPAddresses,
	}
	return certTemplate, nil
}

// getPod fetches the pod that issued a CSR based on the information in the CSR.
// A CSR will contain immutable identity info set by k8s such as:
//
//	spec:
//	 extra:
//	   authentication.kubernetes.io/pod-name:
//	   - prometheus-calico-node-prometheus-0
//	   authentication.kubernetes.io/pod-uid:
//	   - 0993ca7a-3b0b-4e27-ba25-c4296620ea8d
//	 uid: 28610c0a-a4a4-4dc3-9e1d-e8564ce217f6
//	 username: system:serviceaccount:tigera-prometheus:prometheus
func (r ReconcileCSR) getPod(ctx context.Context, csr *certificatesv1.CertificateSigningRequest) (*corev1.Pod, error) {
	username := csr.Spec.Username
	if !strings.HasPrefix(username, "system:serviceaccount:") || strings.Count(username, ":") != 3 {
		// This CSR was not requested by a service account.
		return nil, nil
	}
	namespace := strings.Split(username, ":")[2]
	serviceaccountName := strings.Split(username, ":")[3]

	pod := &corev1.Pod{}
	podName, found := csr.Spec.Extra["authentication.kubernetes.io/pod-name"]
	if !found || len(podName) != 1 {
		return nil, nil
	}
	podUID, found := csr.Spec.Extra["authentication.kubernetes.io/pod-uid"]
	if !found || len(podUID) != 1 {
		return nil, nil
	}

	if err := r.client.Get(ctx, types.NamespacedName{Name: podName[0], Namespace: namespace}, pod); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if podUID[0] == fmt.Sprintf("%s", pod.UID) && serviceaccountName == pod.Spec.ServiceAccountName {
		return pod, nil
	}

	return nil, nil
}
