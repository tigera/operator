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

package installation

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	"k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"

	"github.com/go-logr/logr"
	operator "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/openshift"
	"github.com/tigera/operator/pkg/render"

	configv1 "github.com/openshift/api/config/v1"

	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("installation_controller")
var defaultInstanceKey = client.ObjectKey{Name: "default"}
var openshiftNetworkConfig = "cluster"

// Add creates a new Installation Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) *ReconcileInstallation {
	openshift, err := openshift.IsOpenshift(mgr.GetConfig())
	if err != nil {
		panic(err)
	}
	log.WithValues("openshift", openshift).Info("Checking type of cluster")
	return &ReconcileInstallation{
		client:    mgr.GetClient(),
		scheme:    mgr.GetScheme(),
		watches:   make(map[runtime.Object]struct{}),
		openshift: openshift,
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r *ReconcileInstallation) error {
	// Create a new controller
	c, err := controller.New("tigera-installation-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	r.controller = c

	// Watch for changes to primary resource Installation
	err = c.Watch(&source.Kind{Type: &operator.Installation{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	if r.openshift {
		// Watch for openshift network configuration as well. If we're running in OpenShift, we need to
		// merge this configuration with our own and the write back the status object.
		err = c.Watch(&source.Kind{Type: &configv1.Network{}}, &handler.EnqueueRequestForObject{})
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return err
			}
		}
	}

	// Add watches on component dependencies.
	componentDeps := []runtime.Object{
		&v1.Service{
			TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "elasticsearch-tigera-elasticsearch",
				Namespace: "calico-monitoring",
			},
		},
		&v1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "V1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: "manager-tls",
				//TODO: Read this in from env or something
				Namespace: "tigera-operator",
			},
		},
	}

	for _, dep := range componentDeps {
		err = r.AddWatch(dep)
		if err != nil {
			objMeta := dep.(metav1.ObjectMetaAccessor).GetObjectMeta()
			log.Info("Adding watch on dependency failed", "name", objMeta.GetName(), "namespace", objMeta.GetNamespace(), "error", err.Error())
		}
	}

	for _, t := range secondaryResources() {
		pred := predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				// Ignore updates to objects when metadata.Generation does not change.
				return e.MetaOld.GetGeneration() != e.MetaNew.GetGeneration()
			},
		}
		err = c.Watch(&source.Kind{Type: t}, &handler.EnqueueRequestForOwner{
			IsController: true,
			OwnerType:    &operator.Installation{},
		}, pred)
		if err != nil {
			return err
		}
	}

	return nil
}

// secondaryResources returns a list of the secondary resources that this controller
// monitors for changes. Add resources here which correspond to the resources created by
// this controller.
func secondaryResources() []runtime.Object {
	return []runtime.Object{
		&apps.DaemonSet{},
		&rbacv1.ClusterRole{},
		&rbacv1.ClusterRoleBinding{},
		&v1.ServiceAccount{},
		&v1beta1.APIService{},
		&v1.Service{},
	}
}

var _ reconcile.Reconciler = &ReconcileInstallation{}

// ReconcileInstallation reconciles a Installation object
type ReconcileInstallation struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client     client.Client
	scheme     *runtime.Scheme
	controller controller.Controller
	watches    map[runtime.Object]struct{}
	openshift  bool
}

// AddWatch creates a watch on the given object. Only Create events are processed.
func (r *ReconcileInstallation) AddWatch(obj runtime.Object) error {
	logger := log.WithName("add_watch")
	objMeta := obj.(metav1.ObjectMetaAccessor).GetObjectMeta()
	if _, exists := r.watches[obj]; !exists {
		logger.Info("Watch doesn't exist, creating", "name", objMeta.GetName(), "namespace", objMeta.GetNamespace())
		pred := predicate.Funcs{
			CreateFunc: func(e event.CreateEvent) bool {
				return e.Meta.GetName() == objMeta.GetName() && e.Meta.GetNamespace() == objMeta.GetNamespace()
			},
			UpdateFunc: func(e event.UpdateEvent) bool {
				return e.MetaNew.GetName() == objMeta.GetName() && e.MetaNew.GetNamespace() == objMeta.GetNamespace()
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				return false
			},
		}
		err := r.controller.Watch(&source.Kind{Type: obj}, &handler.EnqueueRequestForObject{}, pred)
		if err == nil {
			r.watches[obj] = struct{}{}
		}
		return err
	}

	logger.Info("Watch exists, skipping", "name", objMeta.GetName(), "namespace", objMeta.GetNamespace())
	return nil
}

// VerifyDependencies checks whether the given component's dependencies exist and are ready. Returns true if the component
// has no dependencies or if all of the component's dependencies are ready.
func (r *ReconcileInstallation) VerifyDependencies(component render.Component) bool {
	logger := log.WithName("verify_dependencies")
	for _, obj := range component.GetComponentDeps() {
		objMeta := obj.(metav1.ObjectMetaAccessor).GetObjectMeta()
		objName := objMeta.GetName()
		objNamespace := objMeta.GetNamespace()

		switch obj.(type) {
		case *v1.Service:
			service := &v1.Service{}
			svcName := types.NamespacedName{Name: objName, Namespace: objNamespace}
			err := r.client.Get(context.Background(), svcName, service)
			if err != nil {
				if apierrors.IsNotFound(err) {
					logger.Info("Service dependency doesn't exist yet", "name", objName, "namespace", objNamespace)
				} else {
					logger.Info("Error getting service", "name", objName, "namespace", objNamespace, "error", err.Error())
				}
				return false
			}

			// If the service exists, check that its ready by looking for at least 1 ready address in all of its
			// endpoints' subsets.
			err = wait.PollImmediate(3*time.Second, 30*time.Second, func() (bool, error) {
				endpoints := &v1.Endpoints{}
				err = r.client.Get(context.Background(), svcName, endpoints)
				if err != nil {
					// If not found, retry.
					if apierrors.IsNotFound(err) {
						logger.Info("Endpoints dependency doesn't exist yet", "name", objName, "namespace", objNamespace)
						return false, nil
					}

					// Any other error, just quit
					return false, err
				}

				for _, subset := range endpoints.Subsets {
					if len(subset.Addresses) == 0 {
						log.Info("Endpoints dependency has 0 ready addresses", "name", objName, "namespace", objNamespace)
						return false, nil
					}
				}
				// If we reach here, all of the endpoints subsets have at least 1 ready address and the service is ready
				logger.Info("Service dependency is ready", "name", objName, "namespace", objNamespace)
				return true, nil
			})

			if err != nil {
				logger.Info("Service dependency check failed", "error", err.Error())
				return false
			}
		}
	}
	return true
}

// Reconcile reads that state of the cluster for a Installation object and makes changes based on the state read
// and what is in the Installation.Spec. The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileInstallation) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.V(1).Info("Reconciling network installation")

	ctx := context.Background()

	// Fetch the Installation instance. We only support a single instance named "default".
	instance := &operator.Installation{}
	err := r.client.Get(ctx, defaultInstanceKey, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			reqLogger.Info("Network installation config not found")
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	err = checkOperatorVersion(instance.Spec.MinimumOperatorVersion)
	if err != nil {
		reqLogger.Info("Invalid version", "err", err.Error(), "version", instance.Spec.Version, "opVersion", instance.Spec.MinimumOperatorVersion)
		return reconcile.Result{}, err
	}

	fillDefaults(instance)
	reqLogger.V(2).Info("Loaded config", "config", instance)

	openshiftConfig := &configv1.Network{}
	if r.openshift {
		// If configured to run in openshift, then also fetch the openshift configuration API.
		reqLogger.V(1).Info("Querying for openshift network config")
		err = r.client.Get(ctx, types.NamespacedName{Name: openshiftNetworkConfig}, openshiftConfig)
		if err != nil {
			// Error reading the object - requeue the request.
			return reconcile.Result{}, err
		}

		// Use the openshift provided CIDRs.
		instance.Spec.IPPools = []operator.IPPool{}
		for _, net := range openshiftConfig.Spec.ClusterNetwork {
			instance.Spec.IPPools = append(instance.Spec.IPPools, operator.IPPool{CIDR: net.CIDR})
		}
	}

	// Validate the configuration.
	if err = validateCustomResource(instance); err != nil {
		return reconcile.Result{}, err
	}

	// TODO: Do this when we know that just calico has deployed, the calico-node,
	// resources have been created, or at least don't gate updating the Status
	// on TSEE components/resource being created.
	if r.openshift {
		// If configured to run in openshift, update the config status with the current state.
		reqLogger.V(1).Info("Updating openshift cluster network status")
		openshiftConfig.Status.ClusterNetwork = openshiftConfig.Spec.ClusterNetwork
		openshiftConfig.Status.ServiceNetwork = openshiftConfig.Spec.ServiceNetwork
		openshiftConfig.Status.ClusterNetworkMTU = 1440
		openshiftConfig.Status.NetworkType = "Calico"
		if err = r.client.Update(ctx, openshiftConfig); err != nil {
			return reconcile.Result{}, err
		}
	}

	// Render the desired components based on our configuration. This represents the desired state of the cluster.
	renderer := render.New(instance, r.client, r.openshift)
	desiredComponents := renderer.Render()

	// Create the desired state objects.
	for _, component := range desiredComponents {
		// Before creating the object, verify that its component dependencies exist. If the component is nil that means
		// we can skip rendering it.
		log.Info("Verifying deps for component")
		if component == nil || !component.Ready(r.client) {
			continue
		}

		for _, obj := range component.GetObjects() {
			// Set Installation instance as the owner and controller.
			if err := controllerutil.SetControllerReference(instance, obj.(metav1.ObjectMetaAccessor).GetObjectMeta(), r.scheme); err != nil {
				return reconcile.Result{}, err
			}

			logCtx := contextLoggerForResource(obj)
			var old runtime.Object = obj.DeepCopyObject()
			var key client.ObjectKey
			key, err = client.ObjectKeyFromObject(obj)
			if err != nil {
				return reconcile.Result{}, err
			}

			err = r.client.Get(ctx, key, old)
			if err != nil {
				if !apierrors.IsNotFound(err) {
					// Anything other than "Not found" we should retry.
					return reconcile.Result{}, err
				}
				// Otherwise, if it was not found, we should create it.
				logCtx.V(2).Info("Object does not exist", "error", err)
			} else {
				logCtx.V(1).Info("Resource already exists, update it")
				err = r.client.Update(ctx, mergeState(obj, old))
				if err != nil {
					logCtx.WithValues("key", key).Info("Failed to update object.")
					return reconcile.Result{}, err
				}
				continue
			}

			logCtx.Info("Creating new object.")
			err = r.client.Create(ctx, obj)
			if err != nil {
				// Hit an error creating desired state object - we need to requeue.
				return reconcile.Result{}, err
			}
		}
	}

	// If the new spec does not require a kube-proxy installation, check if we have one and delete it.
	if !instance.Spec.Components.KubeProxy.Required {
		// Render the objects that we might want to delete.
		cp := instance.DeepCopyObject().(*operator.Installation)
		cp.Spec.Components.KubeProxy.Required = true
		kubeProxyComponent := render.KubeProxy(cp)
		for _, o := range kubeProxyComponent.GetObjects() {
			logCtx := contextLoggerForResource(o)

			// Check if the object exists.
			var key client.ObjectKey
			key, err = client.ObjectKeyFromObject(o)
			logCtx.WithValues("key", key).V(1).Info("Checking if we need to delete object")
			if err = r.client.Get(ctx, key, o); err != nil {
				logCtx.WithValues("key", key, "error", err).Info("Error querying object")
				continue
			}

			// Check if we created it.
			if hasOwnerReference(o, instance, r.scheme) {
				if err = r.client.Delete(ctx, o); err != nil {
					logCtx.WithValues("key", key).Info("Error deleting instance.")
					return reconcile.Result{}, err
				}
				logCtx.WithValues("key", key).Info("Object deleted.")
			}
		}
	}

	// Created successfully - don't requeue
	reqLogger.V(1).Info("Finished reconciling network installation")
	return reconcile.Result{}, nil
}

// mergeState returns the object to pass to Update given the current and desired object states.
func mergeState(desired, current runtime.Object) runtime.Object {
	switch desired.(type) {
	case *v1.Service:
		// Services are a special case since some fields (namely ClusterIP) are defaulted
		// and we need to maintain them on updates.
		oldRV := current.(metav1.ObjectMetaAccessor).GetObjectMeta().GetResourceVersion()
		desired.(metav1.ObjectMetaAccessor).GetObjectMeta().SetResourceVersion(oldRV)
		cs := current.(*v1.Service)
		ds := desired.(*v1.Service)
		ds.Spec.ClusterIP = cs.Spec.ClusterIP
		return ds
	case *batchv1.Job:
		// Jobs have controller-uid values added to spec.selector and spec.template.metadata.labels.
		// spec.selector and podtemplatespec are immutable so just copy real values over to desired state.
		oldRV := current.(metav1.ObjectMetaAccessor).GetObjectMeta().GetResourceVersion()
		desired.(metav1.ObjectMetaAccessor).GetObjectMeta().SetResourceVersion(oldRV)
		cj := current.(*batchv1.Job)
		dj := desired.(*batchv1.Job)
		dj.Spec.Selector = cj.Spec.Selector
		dj.Spec.Template = cj.Spec.Template
		return dj
	default:
		// Default to just using the desired state, with an updated RV.
		oldRV := current.(metav1.ObjectMetaAccessor).GetObjectMeta().GetResourceVersion()
		desired.(metav1.ObjectMetaAccessor).GetObjectMeta().SetResourceVersion(oldRV)
		return desired
	}
}

func contextLoggerForResource(obj runtime.Object) logr.Logger {
	gvk := obj.GetObjectKind().GroupVersionKind()
	name := obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetName()
	namespace := obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetNamespace()
	return log.WithValues("Name", name, "Namespace", namespace, "Kind", gvk.Kind)
}

// hasOwnerReference checks if the given object was created by us (as opposed to another controller).
func hasOwnerReference(obj runtime.Object, instance metav1.Object, scheme *runtime.Scheme) bool {
	ro := instance.(runtime.Object)
	gvk, err := apiutil.GVKForObject(ro, scheme)
	if err != nil {
		return false
	}

	// Compare each of the object's owner references against the object's kind and our instance's name.
	refs := obj.(metav1.ObjectMetaAccessor).GetObjectMeta().GetOwnerReferences()
	for _, r := range refs {
		if r.Kind == gvk.Kind && r.Name == instance.GetName() {
			return true
		}
	}
	return false
}
