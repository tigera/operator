package core

import (
	"context"

	operatorv1alpha1 "github.com/projectcalico/operator/pkg/apis/operator/v1alpha1"
	"github.com/projectcalico/operator/pkg/render"

	apps "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_core")

// Add creates a new Core Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileCore{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("core-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource Core
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.Core{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner Core
	err = c.Watch(&source.Kind{Type: &apps.DaemonSet{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.Core{},
	})
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileCore{}

// ReconcileCore reconciles a Core object
type ReconcileCore struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a Core object and makes changes based on the state read
// and what is in the Core.Spec. The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileCore) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling Core")

	// Fetch the Core instance
	instance := &operatorv1alpha1.Core{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	// Define a new Pod object
	objs := renderObjects(instance)

	// Set Core instance as the owner and controller
	for _, obj := range objs {
		if err := controllerutil.SetControllerReference(instance, obj.(metav1.ObjectMetaAccessor).GetObjectMeta(), r.scheme); err != nil {
			return reconcile.Result{}, err
		}
	}

	// Create the objects.
	for _, obj := range objs {
		var old runtime.Object = obj.DeepCopyObject()
		var key client.ObjectKey
		key, err = client.ObjectKeyFromObject(obj)
		if err != nil {
			return reconcile.Result{}, err
		}
		err = r.client.Get(context.TODO(), key, old)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				// Anything other than "Not found" we should retry.
				return reconcile.Result{}, err
			}
			// Otherwise, if it was not found, we should create it.
		} else {
			// Resource exists, skip it.
			// TODO: Reconcile any changes if the object doesn't match.
			reqLogger.Info("Resource exists")
			return reconcile.Result{}, nil
		}

		reqLogger.WithValues("Resource", obj.GetObjectKind()).Info("Creating new object")
		err = r.client.Create(context.TODO(), obj)
		if err != nil {
			// Hit an error creating object - we need to requeue.
			return reconcile.Result{}, err
		}
	}

	// Created successfully - don't requeue
	return reconcile.Result{}, nil
}

func renderObjects(cr *operatorv1alpha1.Core) []runtime.Object {
	var objs []runtime.Object
	// Only install KubeProxy if required, and do so before installing Node.
	if cr.Spec.RunKubeProxy {
		objs := render.KubeProxy(cr)
		objs = append(objs, render.Node(cr))
	} else {
		objs := render.Node(cr)
	}
	return objs
}
