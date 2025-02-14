package whisker

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/ctrlruntime"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type Status interface {
	Conditions() []metav1.Condition
	SetConditions([]metav1.Condition)
}

type ClientObject[R any] interface {
	*R
	client.Object
}

type ClientObj[CR any, O ClientObject[CR]] interface {
	ClientObject[CR]
	DeepCopy() O
	TigeraStatusResourceName() string
	Status() Status
	FillDefaults()
}

type genericReconciler[CR any, R ClientObject[CR], CliObj ClientObj[CR, R]] struct {
	cli           client.Client
	scheme        *runtime.Scheme
	provider      operatorv1.Provider
	status        status.StatusManager
	clusterDomain string
	log           logr.Logger
	reconciler    TigeraReconciler[CR]

	watchTiers, watchLicenses bool
	// TODO should we just have something more generic? Would be nice to have a single object that can be checked to
	// TODO see if all watches are ready, regardless of the type.
	tierWatchReady, licenseWatchReady *utils.ReadyFlag
}

type params[E any] struct {
	variant             operatorv1.ProductVariant
	installations       *operatorv1.InstallationSpec
	cr                  *E
	tigeraTierAvailable bool
	pullSecrets         []*corev1.Secret
	license             v3.LicenseKey
}

type TigeraReconciler[E any] interface {
	Reconcile(ctx context.Context, params params[E], request reconcile.Request) (reconcile.Result, error)
}

type reconcileOptions struct {
	watchTiers    bool
	watchLicenses bool
}

func newGenericReconciler[CR any, R ClientObject[CR], CliObj ClientObj[CR, R]](
	mgr manager.Manager, recOpts reconcileOptions, opts options.AddOptions,
	reconciler TigeraReconciler[CR],
) (*genericReconciler[CR, R, CliObj], error) {
	r := &genericReconciler[CR, R, CliObj]{
		reconciler:    reconciler,
		watchTiers:    recOpts.watchTiers,
		watchLicenses: recOpts.watchLicenses,
	}

	c, err := ctrlruntime.NewController(controllerName, mgr, controller.Options{Reconciler: r})
	if err != nil {
		return nil, fmt.Errorf("failed to create %s: %w", controllerName, err)
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return nil, err
	}

	// Watch for changes to License and Tier, as their status is used as input to determine whether network policy should be reconciled by this controller.
	if recOpts.watchLicenses {
		r.licenseWatchReady = new(utils.ReadyFlag)
		go utils.WaitToAddLicenseKeyWatch(c, k8sClient, log, r.licenseWatchReady)
	}

	if recOpts.watchTiers {
		r.tierWatchReady = new(utils.ReadyFlag)
		go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, c, k8sClient, log, r.tierWatchReady)
	}

	return &genericReconciler[CR, R, CliObj]{}, nil
}

func (r *genericReconciler[CR, R, CliObj]) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	// Wait for the watches necessary to complete reconciliation before attempting to move forward. There's no point in
	// querying the k8s API and flooding the logs when the reconciler will ultimately fail.
	if ready, message := r.waitForDelayedWatches(); !ready {
		r.status.SetDegraded(operatorv1.ResourceNotReady, message, nil, r.log)
		return reconcile.Result{RequeueAfter: utils.StandardRetry}, nil
	}

	var tigeraTierAvailable bool
	if err := r.cli.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err == nil {
		tigeraTierAvailable = true
	} else if !apierrors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying allow-tigera tier", err, r.log)
		return reconcile.Result{}, err
	}

	var license v3.LicenseKey
	var err error
	if license, err = utils.FetchLicenseKey(ctx, r.cli); err != nil && !apierrors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, r.log)
		return reconcile.Result{}, err
	}

	variant, installation, err := r.getInstallation(ctx)
	if err != nil {
		return reconcile.Result{}, err
	} else if installation == nil {
		return reconcile.Result{}, nil
	}

	cr, err := r.getCR(ctx)
	if err != nil {
		return reconcile.Result{}, err
	} else if cr == nil {
		return reconcile.Result{}, nil
	}
	defer r.status.SetMetaData(cr)

	if request.Name == cr.TigeraStatusResourceName() && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		if err := r.cli.Get(ctx, types.NamespacedName{Name: cr.TigeraStatusResourceName()}, ts); err != nil {
			return reconcile.Result{}, err
		}

		crStatus := cr.Status()
		crStatus.SetConditions(status.UpdateStatusCondition(cr.Status().Conditions(), ts.Status.Conditions))

		if err := r.cli.Status().Update(ctx, cr); err != nil {
			log.WithValues("reason", err).Info(fmt.Sprintf("Failed to create %T status conditions.", cr))
			return reconcile.Result{}, err
		}
	}

	preDefaultPatchFrom := client.MergeFrom(cr.DeepCopy())
	cr.FillDefaults()

	// Write the discovered configuration back to the API. This is essentially a poor-man's defaulting, and
	// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
	if err := r.cli.Patch(ctx, cr, preDefaultPatchFrom); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, err.Error(), err, r.log)
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.cli)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, r.log)
		return reconcile.Result{}, err
	}

	result, err := r.reconciler.Reconcile(ctx, params[CR]{
		variant:             variant,
		installations:       installation,
		cr:                  cr,
		tigeraTierAvailable: tigeraTierAvailable,
		pullSecrets:         pullSecrets,
		license:             license,
	}, request)

	if err != nil {
		r.status.ClearDegraded()
	}

	return result, err
}

func (r *genericReconciler[CR, R, CliObj]) waitForDelayedWatches() (bool, string) {
	// Wait for the license watch to be established.
	if r.watchLicenses && !r.licenseWatchReady.IsReady() {
		return false, "Waiting for License watch to be established"
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if r.watchTiers && !r.tierWatchReady.IsReady() {
		return false, "Waiting for Tier watch to be established"
	}

	return true, ""
}

func (r *genericReconciler[CR, R, CliObj]) getInstallation(ctx context.Context) (operatorv1.ProductVariant, *operatorv1.InstallationSpec, error) {
	variant, installation, err := utils.GetInstallation(ctx, r.cli)
	if err != nil {
		if apierrors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, r.log)
			return "", nil, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, r.log)
		return "", nil, err
	}

	return variant, installation, nil
}

func (r *genericReconciler[CR, R, CliObj]) getCR(ctx context.Context) (CliObj, error) {
	cr := new(CR)

	if err := r.cli.Get(ctx, utils.DefaultTSEEInstanceKey, R(cr)); err != nil {
		if apierrors.IsNotFound(err) {
			r.status.OnCRNotFound()
			return nil, nil
		}

		// TODO should we log the type or implement a Name function for the CR type??
		r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error querying %T", cr), err, r.log)
		return nil, err
	}

	return cr, nil
}
