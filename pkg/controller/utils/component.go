package utils

import (
	"context"
	"reflect"

	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render"

	"github.com/go-logr/logr"
	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type ComponentHandler interface {
	CreateOrUpdate(context.Context, render.Component, *status.StatusManager) error
}

func NewComponentHandler(log logr.Logger, client client.Client, scheme *runtime.Scheme, cr metav1.Object) ComponentHandler {
	return &componentHandler{
		client: client,
		scheme: scheme,
		cr:     cr,
		log:    log,
	}
}

type componentHandler struct {
	client client.Client
	scheme *runtime.Scheme
	cr     metav1.Object
	log    logr.Logger
}

func (c componentHandler) CreateOrUpdate(ctx context.Context, component render.Component, status *status.StatusManager) error {
	// Before creating the component, make sure that it is ready. This provides a hook to do
	// dependency checking for the component.
	cmpLog := c.log.WithValues("component", reflect.TypeOf(component))
	cmpLog.V(2).Info("Checking if component is ready")
	if !component.Ready() {
		cmpLog.Info("Component is not ready, skipping")
		return nil
	}
	cmpLog.V(2).Info("Reconciling")

	// Iterate through each object that comprises the component and attempt to create it,
	// or update it if needed.
	daemonSets := []types.NamespacedName{}
	deployments := []types.NamespacedName{}
	statefulsets := []types.NamespacedName{}
	for _, obj := range component.Objects() {
		// Set CR instance as the owner and controller.
		if err := controllerutil.SetControllerReference(c.cr, obj.(metav1.ObjectMetaAccessor).GetObjectMeta(), c.scheme); err != nil {
			return err
		}

		logCtx := ContextLoggerForResource(c.log, obj)
		var old runtime.Object = obj.DeepCopyObject()
		var key client.ObjectKey
		key, err := client.ObjectKeyFromObject(obj)
		if err != nil {
			return err
		}

		// Keep track of some objects so we can report on their status.
		if obj.GetObjectKind().GroupVersionKind().Kind == "DaemonSet" {
			daemonSets = append(daemonSets, key)
		} else if obj.GetObjectKind().GroupVersionKind().Kind == "Deployment" {
			deployments = append(deployments, key)
		} else if obj.GetObjectKind().GroupVersionKind().Kind == "StatefulSet" {
			statefulsets = append(statefulsets, key)
		}

		// Check to see if the object exists or not.
		err = c.client.Get(ctx, key, old)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				// Anything other than "Not found" we should retry.
				return err
			}

			// Otherwise, if it was not found, we should create it and move on.
			logCtx.V(2).Info("Object does not exist, creating it", "error", err)
			err = c.client.Create(ctx, obj)
			if err != nil {
				return err
			}
			continue
		}

		// The object exists. Update it, unless the user has marked it as "ignored".
		if IgnoreObject(old) {
			logCtx.Info("Ignoring annotated object")
			continue
		}
		logCtx.V(1).Info("Resource already exists, update it")
		err = c.client.Update(ctx, mergeState(obj, old))
		if err != nil {
			logCtx.WithValues("key", key).Info("Failed to update object.")
			return err
		}
		continue
	}
	if status != nil {
		status.SetDaemonsets(daemonSets)
		status.SetDeployments(deployments)
		status.SetStatefulSets(statefulsets)
	}
	cmpLog.Info("Done reconciling component")
	return nil
}

// mergeState returns the object to pass to Update given the current and desired object states.
func mergeState(desired, current runtime.Object) runtime.Object {
	currentMeta := current.(metav1.ObjectMetaAccessor).GetObjectMeta()
	desiredMeta := desired.(metav1.ObjectMetaAccessor).GetObjectMeta()

	// Merge common metadata fields.
	desiredMeta.SetResourceVersion(currentMeta.GetResourceVersion())
	desiredMeta.SetUID(currentMeta.GetUID())
	desiredMeta.SetCreationTimestamp(currentMeta.GetCreationTimestamp())

	switch desired.(type) {
	case *v1.Service:
		// Services are a special case since some fields (namely ClusterIP) are defaulted
		// and we need to maintain them on updates.
		cs := current.(*v1.Service)
		ds := desired.(*v1.Service)
		ds.Spec.ClusterIP = cs.Spec.ClusterIP
		return ds
	case *batchv1.Job:
		// Jobs have controller-uid values added to spec.selector and spec.template.metadata.labels.
		// spec.selector and podtemplatespec are immutable so just copy real values over to desired state.
		cj := current.(*batchv1.Job)
		dj := desired.(*batchv1.Job)
		dj.Spec.Selector = cj.Spec.Selector
		dj.Spec.Template = cj.Spec.Template
		return dj
	case *apps.Deployment:
		cd := current.(*apps.Deployment)
		dd := desired.(*apps.Deployment)
		// Only take the replica count if our desired count is nil so that
		// any Deployments where we specify a replica count we will retain
		// control over the count.
		if dd.Spec.Replicas == nil {
			dd.Spec.Replicas = cd.Spec.Replicas
		}
		return dd
	case *v1.ServiceAccount:
		// ServiceAccounts generate a new token if we don't include the existing one.
		csa := current.(*v1.ServiceAccount)
		dsa := desired.(*v1.ServiceAccount)
		if len(csa.Secrets) != 0 && len(dsa.Secrets) == 0 {
			// Only copy the secrets if they exist, and we haven't specified them explicitly
			// on the new object.
			dsa.Secrets = csa.Secrets
		}
		return dsa
	default:
		// Default to just using the desired state, with an updated RV.
		return desired
	}
}
