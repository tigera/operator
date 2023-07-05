// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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

package utils

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	esv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	"github.com/go-logr/logr"
	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

type ComponentHandler interface {
	CreateOrUpdateOrDelete(context.Context, render.Component, status.StatusManager) error
}

// cr is allowed to be nil in the case we don't want to put ownership on a resource,
// this is useful for CRD management so that they are not removed automatically.
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

func (c componentHandler) createOrUpdateObject(ctx context.Context, obj client.Object, osType rmeta.OSType) error {
	om, ok := obj.(metav1.ObjectMetaAccessor)
	if !ok {
		return fmt.Errorf("Object is not ObjectMetaAccessor")
	}

	multipleOwners := checkIfMultipleOwnersLabel(om.GetObjectMeta())
	// Add owner ref for controller owned resources,
	switch obj.(type) {
	case *v3.UISettings:
		// Never add controller ref for UISettings since these are always GCd through the UISettingsGroup.
	default:
		if c.cr != nil && !skipAddingOwnerReference(c.cr, om.GetObjectMeta()) {
			if multipleOwners {
				if err := controllerutil.SetOwnerReference(c.cr, om.GetObjectMeta(), c.scheme); err != nil {
					return err
				}
			} else {
				if err := controllerutil.SetControllerReference(c.cr, om.GetObjectMeta(), c.scheme); err != nil {
					return err
				}
			}
		}
	}

	logCtx := ContextLoggerForResource(c.log, obj)
	key := client.ObjectKeyFromObject(obj)

	// Ensure that if the object is something the creates a pod that it is scheduled on nodes running the operating
	// system as specified by the osType.
	ensureOSSchedulingRestrictions(obj, osType)

	// Make sure any objects with images also have an image pull policy.
	modifyPodSpec(obj, setImagePullPolicy)

	// Make sure we have our standard selector and pod labels
	setStandardSelectorAndLabels(obj)

	cur, ok := obj.DeepCopyObject().(client.Object)
	if !ok {
		logCtx.V(2).Info("Failed converting object", "obj", obj)
		return fmt.Errorf("Failed converting object %+v", obj)
	}
	// Check to see if the object exists or not.
	err := c.client.Get(ctx, key, cur)
	if err != nil {
		if !errors.IsNotFound(err) {
			// Anything other than "Not found" we should retry.
			return err
		}

		// Otherwise, if it was not found, we should create it and move on.
		logCtx.V(2).Info("Object does not exist, creating it", "error", err)
		if multipleOwners {
			labels := om.GetObjectMeta().GetLabels()
			delete(labels, common.MultipleOwnersLabel)
			om.GetObjectMeta().SetLabels(labels)
		}
		err = c.client.Create(ctx, obj)
		if err != nil {
			return err
		}
		return nil
	}

	// The object exists. Update it, unless the user has marked it as "ignored".
	if IgnoreObject(cur) {
		logCtx.Info("Ignoring annotated object")
		return nil
	}
	logCtx.V(2).Info("Resource already exists, update it")

	// if mergeState returns nil we don't want to update the object
	if mobj := mergeState(obj, cur); mobj != nil {
		switch obj.(type) {
		case *batchv1.Job:
			// Jobs can't be updated, they can only be deleted then created
			if err := c.client.Delete(ctx, obj); err != nil {
				logCtx.WithValues("key", key).Info("Failed to delete job for recreation.")
				return err
			}

			// Do the Create() with the merged object so that we preserve external labels/annotations.
			resetMetadataForCreate(mobj)
			if err := c.client.Create(ctx, mobj); err != nil {
				return err
			}
			return nil
		case *v1.Secret:
			objSecret := obj.(*v1.Secret)
			curSecret := cur.(*v1.Secret)
			// Secret types are immutable, we need to delete the old version if the type has changed. If the
			// object type is unset, it will result in SecretTypeOpaque, so this difference can be excluded.
			if objSecret.Type != curSecret.Type &&
				!(len(objSecret.Type) == 0 && curSecret.Type == v1.SecretTypeOpaque) {
				if err := c.client.Delete(ctx, obj); err != nil {
					logCtx.WithValues("key", key).Info("Failed to delete secret for recreation.")
					return err
				}

				// Do the Create() with the merged object so that we preserve external labels/annotations.
				resetMetadataForCreate(mobj)
				if err := c.client.Create(ctx, mobj); err != nil {
					return err
				}
				return nil
			}
		case *v1.Service:
			objService := obj.(*v1.Service)
			curService := cur.(*v1.Service)
			if objService.Spec.ClusterIP == "None" && curService.Spec.ClusterIP != "None" {
				// We don't want this service to have a cluster IP, but it has got one already.  Need to recreate
				// the service to remove it.
				logCtx.WithValues("key", key).Info("Service already exists and has unwanted ClusterIP, recreating service.")
				if err := c.client.Delete(ctx, obj); err != nil {
					logCtx.WithValues("key", key).Error(err, "Failed to delete Service for recreation.")
					return err
				}

				// Do the Create() with the merged object so that we preserve external labels/annotations.
				resetMetadataForCreate(mobj)
				if err := c.client.Create(ctx, mobj); err != nil {
					logCtx.WithValues("key", key).Error(err, "Failed to recreate service.", "obj", obj)
					return err
				}
				return nil
			}
		}
		if err := c.client.Update(ctx, mobj); err != nil {
			logCtx.WithValues("key", key).Info("Failed to update object.")
			return err
		}
	}
	return nil
}

func resetMetadataForCreate(obj client.Object) {
	obj.SetResourceVersion("")
	obj.SetUID("")
	obj.SetCreationTimestamp(metav1.Time{})
}

func (c componentHandler) CreateOrUpdateOrDelete(ctx context.Context, component render.Component, status status.StatusManager) error {
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
	var daemonSets []types.NamespacedName
	var deployments []types.NamespacedName
	var statefulsets []types.NamespacedName
	var cronJobs []types.NamespacedName

	objsToCreate, objsToDelete := component.Objects()
	osType := component.SupportedOSType()

	for _, obj := range objsToCreate {
		key := client.ObjectKeyFromObject(obj)

		// Pass in a DeepCopy so any modifications made by createOrUpdateObject won't be included
		// if we need to retry the function
		err := c.createOrUpdateObject(ctx, obj.DeepCopyObject().(client.Object), osType)
		// If the error is a resource Conflict, try the update again
		if err != nil && errors.IsConflict(err) {
			cmpLog.WithValues("key", key, "conflict_message", err).Info("Failed to update object, retrying.")
			err = c.createOrUpdateObject(ctx, obj, osType)
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		}

		// Keep track of some objects so we can report on their status.
		switch obj.(type) {
		case *apps.Deployment:
			deployments = append(deployments, key)
		case *apps.DaemonSet:
			daemonSets = append(daemonSets, key)
		case *apps.StatefulSet:
			statefulsets = append(statefulsets, key)
		case *batchv1.CronJob:
			cronJobs = append(cronJobs, key)
		}

		continue
	}
	if status != nil {
		status.AddDaemonsets(daemonSets)
		status.AddDeployments(deployments)
		status.AddStatefulSets(statefulsets)
		status.AddCronJobs(cronJobs)
	}

	for _, obj := range objsToDelete {
		err := c.client.Delete(ctx, obj)
		if err != nil && !errors.IsNotFound(err) {
			logCtx := ContextLoggerForResource(c.log, obj)
			logCtx.Error(err, fmt.Sprintf("Error deleting object %v", obj))
			return err
		}

		key := client.ObjectKeyFromObject(obj)
		if status != nil {
			switch obj.(type) {
			case *apps.Deployment:
				status.RemoveDeployments(key)
			case *apps.DaemonSet:
				status.RemoveDaemonsets(key)
			case *apps.StatefulSet:
				status.RemoveStatefulSets(key)
			case *batchv1.CronJob:
				status.RemoveCronJobs(key)
			}
		}
	}

	cmpLog.V(1).Info("Done reconciling component")
	// TODO Get each controller to explicitly call ReadyToMonitor on the status manager instead of doing it here.
	if status != nil {
		status.ReadyToMonitor()
	}
	return nil
}

// skipAddingOwnerReference returns true if owner is a namespaced resource and
// controlled object is a cluster scoped resource.
func skipAddingOwnerReference(owner, controlled metav1.Object) bool {
	ownerNs := owner.GetNamespace()
	controlledNs := controlled.GetNamespace()
	if ownerNs != "" && controlledNs == "" {
		return true
	}
	return false
}

func checkIfMultipleOwnersLabel(controlled metav1.Object) bool {
	labels := controlled.GetLabels()
	_, ok := labels[common.MultipleOwnersLabel]
	return ok
}

// mergeState returns the object to pass to Update given the current and desired object states.
func mergeState(desired client.Object, current runtime.Object) client.Object {
	// Take a copy of the desired object, so we can merge values into it without
	// adjusting the caller's copy.
	desired = desired.DeepCopyObject().(client.Object)

	currentMeta := current.(metav1.ObjectMetaAccessor).GetObjectMeta()
	desiredMeta := desired.(metav1.ObjectMetaAccessor).GetObjectMeta()

	// Merge common metadata fields if not present on the desired state.
	if desiredMeta.GetResourceVersion() == "" {
		desiredMeta.SetResourceVersion(currentMeta.GetResourceVersion())
	}
	if desiredMeta.GetUID() == "" {
		desiredMeta.SetUID(currentMeta.GetUID())
	}
	if reflect.DeepEqual(desiredMeta.GetCreationTimestamp(), metav1.Time{}) {
		desiredMeta.SetCreationTimestamp(currentMeta.GetCreationTimestamp())
	}

	// Merge annotations by reconciling the ones that components expect, but leaving everything else
	// as-is.
	currentAnnotations := common.MapExistsOrInitialize(currentMeta.GetAnnotations())
	desiredAnnotations := common.MapExistsOrInitialize(desiredMeta.GetAnnotations())
	mergedAnnotations := common.MergeMaps(currentAnnotations, desiredAnnotations)
	desiredMeta.SetAnnotations(mergedAnnotations)

	// Merge labels by reconciling the ones that components expect, but leaving everything else
	// as-is.
	currentLabels := common.MapExistsOrInitialize(currentMeta.GetLabels())
	desiredLabels := common.MapExistsOrInitialize(desiredMeta.GetLabels())
	mergedLabels := common.MergeMaps(currentLabels, desiredLabels)
	desiredMeta.SetLabels(mergedLabels)

	if checkIfMultipleOwnersLabel(desiredMeta) {
		currentOwnerReferences := currentMeta.GetOwnerReferences()
		desiredOwnerReferences := desiredMeta.GetOwnerReferences()
		mergedOwnerReferences := common.MergeOwnerReferences(desiredOwnerReferences, currentOwnerReferences)
		desiredMeta.SetOwnerReferences(mergedOwnerReferences)
		labels := desiredMeta.GetLabels()
		delete(labels, common.MultipleOwnersLabel)
		desiredMeta.SetLabels(labels)
	}

	switch desired.(type) {
	case *v1.Service:
		// Services are a special case since some fields (namely ClusterIP) are defaulted
		// and we need to maintain them on updates.
		cs := current.(*v1.Service)
		ds := desired.(*v1.Service)
		if ds.Spec.ClusterIP != "None" {
			// We want this service to keep its cluster IP.
			ds.Spec.ClusterIP = cs.Spec.ClusterIP
		}
		return ds
	case *batchv1.Job:
		cj := current.(*batchv1.Job)
		dj := desired.(*batchv1.Job)

		// We're only comparing jobs based off of annotations for now so we can send a signal to recreate a job. Later
		// we might want to have some better comparison of jobs so that a changed in the container spec would trigger
		// a recreation of the job
		if reflect.DeepEqual(cj.Spec.Template.Annotations, dj.Spec.Template.Annotations) {
			return nil
		}

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

		// Merge the template's labels.
		currentLabels := common.MapExistsOrInitialize(cd.Spec.Template.GetObjectMeta().GetLabels())
		desiredLabels := common.MapExistsOrInitialize(dd.Spec.Template.GetObjectMeta().GetLabels())
		mergedLabels := common.MergeMaps(currentLabels, desiredLabels)
		dd.Spec.Template.SetLabels(mergedLabels)

		// Merge the template's annotations.
		currentAnnotations := common.MapExistsOrInitialize(cd.Spec.Template.GetObjectMeta().GetAnnotations())
		desiredAnnotations := common.MapExistsOrInitialize(dd.Spec.Template.GetObjectMeta().GetAnnotations())
		mergedAnnotations := common.MergeMaps(currentAnnotations, desiredAnnotations)
		dd.Spec.Template.SetAnnotations(mergedAnnotations)

		return dd
	case *apps.DaemonSet:
		cd := current.(*apps.DaemonSet)
		dd := desired.(*apps.DaemonSet)

		// Merge the template's labels.
		currentLabels := common.MapExistsOrInitialize(cd.Spec.Template.GetObjectMeta().GetLabels())
		desiredLabels := common.MapExistsOrInitialize(dd.Spec.Template.GetObjectMeta().GetLabels())
		mergedLabels := common.MergeMaps(currentLabels, desiredLabels)
		dd.Spec.Template.SetLabels(mergedLabels)

		// Merge the template's annotations.
		currentAnnotations := common.MapExistsOrInitialize(cd.Spec.Template.GetObjectMeta().GetAnnotations())
		desiredAnnotations := common.MapExistsOrInitialize(dd.Spec.Template.GetObjectMeta().GetAnnotations())
		mergedAnnotations := common.MergeMaps(currentAnnotations, desiredAnnotations)
		dd.Spec.Template.SetAnnotations(mergedAnnotations)

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
	case *esv1.Elasticsearch:
		// Only update if the spec has changed
		csa := current.(*esv1.Elasticsearch)
		dsa := desired.(*esv1.Elasticsearch)

		if reflect.DeepEqual(csa.Spec, dsa.Spec) {
			return csa
		}

		// ECK sets these values so we need to copy them over to avoid and update battle
		// Note: This should be revisited when the ECK version moves to GA, as it would be impossible to remove annotations
		// or finalizers from Elasticsearch.
		dsa.Annotations = csa.Annotations
		dsa.Finalizers = csa.Finalizers
		dsa.Status = csa.Status
		return dsa
	case *kbv1.Kibana:
		// Only update if the spec has changed
		csa := current.(*kbv1.Kibana)
		dsa := desired.(*kbv1.Kibana)
		if reflect.DeepEqual(csa.Spec, dsa.Spec) {
			return csa
		}

		// ECK sets these values so we need to copy them over to avoid and update battle
		// Note: This should be revisited when the ECK version moves to GA, as it would be impossible to remove annotations
		// or finalizers from Kibana.
		dsa.Annotations = csa.Annotations
		dsa.Finalizers = csa.Finalizers
		dsa.Spec.ElasticsearchRef = csa.Spec.ElasticsearchRef
		dsa.Status = csa.Status
		return dsa
	case *v3.UISettings:
		// Only update if the spec has changed
		cui := current.(*v3.UISettings)
		dui := desired.(*v3.UISettings)
		if reflect.DeepEqual(cui.Spec, dui.Spec) {
			return cui
		}

		// UISettings are always owned by the group, so never modify the OwnerReferences that are returned by the
		// APIServer.
		dui.SetOwnerReferences(cui.GetOwnerReferences())
		return dui
	case *v3.NetworkPolicy:
		cnp := current.(*v3.NetworkPolicy)
		dnp := desired.(*v3.NetworkPolicy)
		if reflect.DeepEqual(cnp.Spec, dnp.Spec) {
			return nil
		}
		return dnp
	case *v3.Tier:
		ct := current.(*v3.Tier)
		dt := desired.(*v3.Tier)
		if reflect.DeepEqual(ct.Spec, dt.Spec) {
			return nil
		}
		return dt
	default:
		// Default to just using the desired state, with an updated RV.
		return desired
	}
}

// modifyPodSpec is a helper for pulling out pod specifications from an arbitrary object.
func modifyPodSpec(obj client.Object, f func(*v1.PodSpec)) {
	switch x := obj.(type) {
	case *v1.PodTemplate:
		f(&x.Template.Spec)
	case *apps.Deployment:
		f(&x.Spec.Template.Spec)
	case *apps.DaemonSet:
		f(&x.Spec.Template.Spec)
	case *apps.StatefulSet:
		f(&x.Spec.Template.Spec)
	case *batchv1.CronJob:
		f(&x.Spec.JobTemplate.Spec.Template.Spec)
	case *batchv1.Job:
		f(&x.Spec.Template.Spec)
	case *kbv1.Kibana:
		f(&x.Spec.PodTemplate.Spec)
	case *esv1.Elasticsearch:
		// elasticsearch resource describes multiple nodeSets which each have a pod spec.
		nodeSets := x.Spec.NodeSets
		for i := range nodeSets {
			f(&nodeSets[i].PodTemplate.Spec)
		}
	}
}

// setImagePullPolicy ensures that an image pull policy is set if not set already.
func setImagePullPolicy(podSpec *v1.PodSpec) {
	for i := range podSpec.Containers {
		if len(podSpec.Containers[i].ImagePullPolicy) == 0 {
			podSpec.Containers[i].ImagePullPolicy = v1.PullIfNotPresent
		}
	}
}

// ensureOSSchedulingRestrictions ensures that if obj is a type that creates pods and if osType is not OSTypeAny that a
// node selector is set on the pod template for the "kubernetes.io/os" label to ensure that the pod is scheduled
// on a node running an operating system as specified by osType.
func ensureOSSchedulingRestrictions(obj client.Object, osType rmeta.OSType) {
	if osType == rmeta.OSTypeAny {
		return
	}

	// Some object types don't have a v1.PodSpec an instead use a custom spec. Handle those here.
	switch x := obj.(type) {
	case *monitoringv1.Alertmanager:
		// Prometheus operator types don't have a template spec which is of v1.PodSpec type.
		// We can't add it to the podSpecs list and assign osType in the for loop below.
		podSpec := &x.Spec
		if podSpec.NodeSelector == nil {
			podSpec.NodeSelector = make(map[string]string)
		}
		podSpec.NodeSelector["kubernetes.io/os"] = string(osType)
		return
	case *monitoringv1.Prometheus:
		// Prometheus operator types don't have a template spec which is of v1.PodSpec type.
		// We can't add it to the podSpecs list and assign osType in the for loop below.
		podSpec := &x.Spec
		if podSpec.NodeSelector == nil {
			podSpec.NodeSelector = make(map[string]string)
		}
		podSpec.NodeSelector["kubernetes.io/os"] = string(osType)
		return
	}

	// Handle objects that do use a v1.PodSpec.
	f := func(podSpec *v1.PodSpec) {
		if podSpec.NodeSelector == nil {
			podSpec.NodeSelector = make(map[string]string)
		}
		podSpec.NodeSelector["kubernetes.io/os"] = string(osType)
	}
	modifyPodSpec(obj, f)
}

// setStandardSelectorAndLabels will set the k8s-app and app.kubernetes.io/name Labels on the podTemplates
// for Deployments and Daemonsets. If there is no Selector specified a selector will also be added
// that selects the k8s-app label.
func setStandardSelectorAndLabels(obj client.Object) {
	var podTemplate *v1.PodTemplateSpec
	var name string
	switch obj := obj.(type) {
	case *apps.Deployment:
		d := obj
		name = d.ObjectMeta.Name
		if d.ObjectMeta.Labels == nil {
			d.ObjectMeta.Labels = make(map[string]string)
		}
		d.ObjectMeta.Labels["k8s-app"] = name
		d.ObjectMeta.Labels["app.kubernetes.io/name"] = name
		if d.Spec.Selector == nil {
			d.Spec.Selector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": name,
				},
			}
		}
		podTemplate = &d.Spec.Template
	case *apps.DaemonSet:
		d := obj
		name = d.ObjectMeta.Name
		if d.Spec.Selector == nil {
			d.Spec.Selector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app": name,
				},
			}
		}
		podTemplate = &d.Spec.Template
	default:
		return
	}

	if podTemplate.ObjectMeta.Labels == nil {
		podTemplate.ObjectMeta.Labels = make(map[string]string)
	}
	podTemplate.ObjectMeta.Labels["k8s-app"] = name
	podTemplate.ObjectMeta.Labels["app.kubernetes.io/name"] = name
}

// ReadyFlag is used to synchronize access to a boolean flag
// flag that can be shared between go routines. The flag can be
// marked as ready once,as part of a initialization procedure and
// read multiple times afterwards
type ReadyFlag struct {
	mu      sync.RWMutex
	isReady bool
}

// IsReady returns true if was marked as ready
func (r *ReadyFlag) IsReady() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.isReady
}

// MarkAsReady sets the flag as true
func (r *ReadyFlag) MarkAsReady() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.isReady = true
}
