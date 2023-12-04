package csr

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
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
	"github.com/tigera/operator/pkg/render"
	rmonitor "github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
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

// allowedAssets In order to prevent any abuse of this controller in order to obtain a fraudulent certificate, this controller
// will only approve a pre-defined list of assets, based on their 'requestor', dns names and namespaces.
// Some of the information a CSR will contain:
//   - Requestor: this is the user identity tied to the request. This will be matched against the sa + namespace.
//   - Name: The name is based on the secret name + a pod suffix. Because this is deterministic, we can use it as the key
//     to index of this map.
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

// ReconcileCSR Components created by this operator may submit certificate signing requests against k8s under certain
// conditions for signer name "tigera.io/operator-signer". This is the controller that monitors, approves and signs
// these CSRs. It will only sign requests that are pre-defined and reject others in order to avoid any abuse.
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
		certificateTemplate, err := r.validate(ctx, &csr)
		if err != nil {
			if errors.As(err, &invalidCertificateRequestError{}) {
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
			// Validation failed due to an error unrelated to the CSR itself.
			return reconcile.Result{}, err
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

// invalidCertificateRequestError is an error that indicates a problem with the CSR and can help us differentiate with
// other (unforeseen) system / client library errors.
type invalidCertificateRequestError struct {
	message string
}

func (v invalidCertificateRequestError) Error() string {
	return v.message
}

func (r ReconcileCSR) validate(ctx context.Context, csr *certificatesv1.CertificateSigningRequest) (*x509.Certificate, error) {
	firstBlock, restBlocks := pem.Decode(csr.Spec.Request)
	if firstBlock == nil {
		return nil, invalidCertificateRequestError{fmt.Sprintf("cannot parse certificate request for CSR with name %s", csr.Name)}
	}
	if len(restBlocks) != 0 {
		return nil, invalidCertificateRequestError{fmt.Sprintf("unexpected (multiple) pem blocks for CSR with name %s", csr.Name)}
	}

	certificateRequest, err := x509.ParseCertificateRequest(firstBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if err = certificateRequest.CheckSignature(); err != nil {
		return nil, invalidCertificateRequestError{err.Error()}
	}

	// The CSRName is formatted as "<secretName>:<podName>".
	secretName := strings.Split(csr.Name, ":")[0]

	// Validate whether this is a CSR we monitor at all.
	asset, ok := r.allowedTLSAssets[secretName]
	if !ok {
		return nil, invalidCertificateRequestError{fmt.Sprintf("this controller is not configured to sign secretName: %s", secretName)}
	}

	// Validate whether the requestor of the CSR is registered for the given CSR
	if fmt.Sprintf("system:serviceaccount:%s:%s", asset.serviceaccountNamespace, asset.serviceaccountName) != csr.Spec.Username {
		return nil, invalidCertificateRequestError{fmt.Sprintf("invalid requestor %s for CSR with name %s", csr.Spec.Username, csr.Name)}
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
			return nil, invalidCertificateRequestError{fmt.Sprintf("invalid dns name \"%s\" found in CSR with name %s", name, csr.Name)}
		}
	}

	if len(certificateRequest.IPAddresses) == 1 {
		// Validate the IP address that is requested in the CSR matches the pod IP of the requestor.
		label, ok := csr.Labels[render.AppLabelName]
		if !ok {
			return nil, invalidCertificateRequestError{fmt.Sprintf("unable to find expected k8s-app label for CSR with name %s", csr.Name)}
		}
		podList := &corev1.PodList{}
		err = r.client.List(ctx, podList, &client.ListOptions{LabelSelector: labels.SelectorFromSet(map[string]string{render.AppLabelName: label}), Namespace: asset.serviceaccountNamespace})
		if err != nil {
			return nil, fmt.Errorf("unexpected server error while listing pods by label for CSR %s", csr.Name)
		}
		var foundIP bool
		for _, pod := range podList.Items {
			if pod.Status.PodIP == certificateRequest.IPAddresses[0].String() {
				foundIP = true
				break
			}
		}
		if !foundIP {
			return nil, invalidCertificateRequestError{fmt.Sprintf("invalid pod IP for CSR with name %s", csr.Name)}
		}
	} else if len(certificateRequest.IPAddresses) > 1 {
		return nil, invalidCertificateRequestError{fmt.Sprintf("unable request more than 1 IP for CSR with name %s", csr.Name)}
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
