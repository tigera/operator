// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

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

	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	"github.com/go-logr/logr"
	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta "k8s.io/api/batch/v1beta1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"

	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/render"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
)

type ComponentHandler interface {
	CreateOrUpdateOrDelete(context.Context, render.Component, status.StatusManager) error
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
		om, ok := obj.(metav1.ObjectMetaAccessor)
		if !ok {
			return fmt.Errorf("Object is not ObjectMetaAccessor")
		}
		if err := controllerutil.SetControllerReference(c.cr, om.GetObjectMeta(), c.scheme); err != nil {
			return err
		}

		logCtx := ContextLoggerForResource(c.log, obj)
		key := client.ObjectKeyFromObject(obj)

		// Ensure that if the object is something the creates a pod that it is scheduled on nodes running the operating
		// system as specified by the osType.
		ensureOSSchedulingRestrictions(obj, osType)

		// Keep track of some objects so we can report on their status.
		switch obj.(type) {
		case *apps.Deployment:
			deployments = append(deployments, key)
		case *apps.DaemonSet:
			daemonSets = append(daemonSets, key)
		case *apps.StatefulSet:
			statefulsets = append(statefulsets, key)
		case *batchv1beta.CronJob:
			cronJobs = append(cronJobs, key)
		}

		cur, ok := obj.DeepCopyObject().(client.Object)
		if !ok {
			logCtx.V(2).Info("Failed converting object", "obj", obj)
			return fmt.Errorf("Failed converting object %+v", obj)
		}
		// Check to see if the object exists or not.
		err := c.client.Get(ctx, key, cur)
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
		if IgnoreObject(cur) {
			logCtx.Info("Ignoring annotated object")
			continue
		}
		logCtx.V(1).Info("Resource already exists, update it")

		// if mergeState returns nil we don't want to update the object
		if mobj := mergeState(obj, cur); mobj != nil {
			switch obj.(type) {
			case *batchv1.Job:
				// Jobs can't be updated, they can't only be deleted then created
				if err := c.client.Delete(ctx, obj); err != nil {
					logCtx.WithValues("key", key).Info("Failed to delete job for recreation.")
					return err
				}

				if err := c.client.Create(ctx, obj); err != nil {
					return err
				}
			default:
				if err := c.client.Update(ctx, mobj); err != nil {
					logCtx.WithValues("key", key).Info("Failed to update object.")
					return err
				}
			}
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
			case *batchv1beta.CronJob:
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

// mergeState returns the object to pass to Update given the current and desired object states.
func mergeState(desired client.Object, current runtime.Object) client.Object {
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
	currentAnnotations := mapExistsOrInitialize(currentMeta.GetAnnotations())
	desiredAnnotations := mapExistsOrInitialize(desiredMeta.GetAnnotations())
	mergedAnnotations := mergeAnnotations(currentAnnotations, desiredAnnotations)
	desiredMeta.SetAnnotations(mergedAnnotations)

	switch desired.(type) {
	case *v1.Service:
		// Services are a special case since some fields (namely ClusterIP) are defaulted
		// and we need to maintain them on updates.
		cs := current.(*v1.Service)
		ds := desired.(*v1.Service)
		ds.Spec.ClusterIP = cs.Spec.ClusterIP
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
	default:
		// Default to just using the desired state, with an updated RV.
		return desired
	}
}

// ensureOSSchedulingRestrictions ensures that if obj is a type that creates pods and if osType is not OSTypeAny that a
// node selector is set on the pod template for the "kubernetes.io/os" label to ensure that the pod is scheduled
// on a node running an operating system as specified by osType.
func ensureOSSchedulingRestrictions(obj client.Object, osType rmeta.OSType) {
	if osType == rmeta.OSTypeAny {
		return
	}

	var podSpecs []*v1.PodSpec
	switch obj.(type) {
	case *v1.PodTemplate:
		podSpecs = []*v1.PodSpec{&obj.(*v1.PodTemplate).Template.Spec}
	case *apps.Deployment:
		podSpecs = []*v1.PodSpec{&obj.(*apps.Deployment).Spec.Template.Spec}
	case *apps.DaemonSet:
		podSpecs = []*v1.PodSpec{&obj.(*apps.DaemonSet).Spec.Template.Spec}
	case *apps.StatefulSet:
		podSpecs = []*v1.PodSpec{&obj.(*apps.StatefulSet).Spec.Template.Spec}
	case *batchv1beta.CronJob:
		podSpecs = []*v1.PodSpec{&obj.(*batchv1beta.CronJob).Spec.JobTemplate.Spec.Template.Spec}
	case *batchv1.Job:
		podSpecs = []*v1.PodSpec{&obj.(*batchv1.Job).Spec.Template.Spec}
	case *kbv1.Kibana:
		podSpecs = []*v1.PodSpec{&obj.(*kbv1.Kibana).Spec.PodTemplate.Spec}
	case *esv1.Elasticsearch:
		// elasticsearch resource describes multiple nodeSets which each have a nodeSelector.
		nodeSets := obj.(*esv1.Elasticsearch).Spec.NodeSets
		for i := range nodeSets {
			podSpecs = append(podSpecs, &nodeSets[i].PodTemplate.Spec)
		}
	case *monitoringv1.Alertmanager:
		// Prometheus operator types don't have a template spec which is of v1.PodSpec type.
		// We can't add it to the podSpecs list and assign osType in the for loop below.
		podSpec := &obj.(*monitoringv1.Alertmanager).Spec
		podSpec.NodeSelector = map[string]string{"kubernetes.io/os": string(osType)}
		return
	case *monitoringv1.Prometheus:
		// Prometheus operator types don't have a template spec which is of v1.PodSpec type.
		// We can't add it to the podSpecs list and assign osType in the for loop below.
		podSpec := &obj.(*monitoringv1.Prometheus).Spec
		podSpec.NodeSelector = map[string]string{"kubernetes.io/os": string(osType)}
		return
	default:
		return
	}

	for _, podSpec := range podSpecs {
		if podSpec.NodeSelector == nil {
			podSpec.NodeSelector = make(map[string]string)
		}
		podSpec.NodeSelector["kubernetes.io/os"] = string(osType)
	}
}

// mergeAnnotations merges current and desired annotations. If both current and desired annotations contain the same key, the
// desired annotation, i.e, the ones that the operators Components specify take preference.
func mergeAnnotations(current, desired map[string]string) map[string]string {
	for k, v := range current {
		// Copy over annotations that should be copied.
		if _, ok := desired[k]; !ok {
			desired[k] = v
		}
	}
	return desired
}

func mapExistsOrInitialize(m map[string]string) map[string]string {
	if m != nil {
		return m
	}
	return make(map[string]string)
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
