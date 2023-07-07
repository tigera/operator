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

package initializer

import (
	"context"
	"fmt"

	"github.com/elastic/cloud-on-k8s/v2/pkg/utils/stringsutil"

	kbv1 "github.com/elastic/cloud-on-k8s/v2/pkg/apis/kibana/v1"
	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
)

var log = logf.Log.WithName("controller_logstorage")

const (
	DefaultElasticsearchStorageClass = "tigera-elasticsearch"
	LogStorageFinalizer              = "tigera.io/eck-cleanup"
	ResourceName                     = "log-storage"
	defaultEckOperatorMemorySetting  = "512Mi"
)

// Add creates a new LogStorage Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		return nil
	}

	// Create the reconciler
	r := &LogStorageInitializer{
		client:      mgr.GetClient(),
		scheme:      mgr.GetScheme(),
		multiTenant: opts.MultiTenant,
		status:      status.New(mgr.GetClient(), ResourceName, opts.KubernetesVersion),
	}
	r.status.Run(opts.ShutdownContext)

	// Create a controller using the reconciler and register it with the manager to receive reconcile calls.
	c, err := controller.New("log-storage-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Configure watches for operator.tigera.io APIs this controller cares about.
	if err = c.Watch(&source.Kind{Type: &operatorv1.LogStorage{}}, &handler.EnqueueRequestForObject{}); err != nil {
		return fmt.Errorf("log-storage-controller failed to watch LogStorage resource: %w", err)
	}

	return nil
}

var _ reconcile.Reconciler = &LogStorageInitializer{}

// LogStorageInitializer initializes a LogStorage object for sub controllers to use
// by performing validation and defaulting, and marking the resource as available.
type LogStorageInitializer struct {
	client      client.Client
	scheme      *runtime.Scheme
	status      status.StatusManager
	provider    operatorv1.Provider
	multiTenant bool
}

// fillDefaults populates the default values onto an LogStorage object.
func fillDefaults(opr *operatorv1.LogStorage) {
	if opr.Spec.Retention == nil {
		opr.Spec.Retention = &operatorv1.Retention{}
	}

	if opr.Spec.Retention.Flows == nil {
		var fr int32 = 8
		opr.Spec.Retention.Flows = &fr
	}
	if opr.Spec.Retention.AuditReports == nil {
		var arr int32 = 91
		opr.Spec.Retention.AuditReports = &arr
	}
	if opr.Spec.Retention.Snapshots == nil {
		var sr int32 = 91
		opr.Spec.Retention.Snapshots = &sr
	}
	if opr.Spec.Retention.ComplianceReports == nil {
		var crr int32 = 91
		opr.Spec.Retention.ComplianceReports = &crr
	}
	if opr.Spec.Retention.DNSLogs == nil {
		var dlr int32 = 8
		opr.Spec.Retention.DNSLogs = &dlr
	}
	if opr.Spec.Retention.BGPLogs == nil {
		var bgp int32 = 8
		opr.Spec.Retention.BGPLogs = &bgp
	}

	if opr.Spec.Indices == nil {
		opr.Spec.Indices = &operatorv1.Indices{}
	}

	if opr.Spec.Indices.Replicas == nil {
		var replicas int32 = render.DefaultElasticsearchReplicas
		opr.Spec.Indices.Replicas = &replicas
	}

	if opr.Spec.StorageClassName == "" {
		opr.Spec.StorageClassName = DefaultElasticsearchStorageClass
	}

	if opr.Spec.Nodes == nil {
		opr.Spec.Nodes = &operatorv1.Nodes{Count: 1}
	}

	if opr.Spec.ComponentResources == nil {
		limits := corev1.ResourceList{}
		requests := corev1.ResourceList{}
		limits[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)
		requests[corev1.ResourceMemory] = resource.MustParse(defaultEckOperatorMemorySetting)
		opr.Spec.ComponentResources = []operatorv1.LogStorageComponentResource{
			{
				ComponentName: operatorv1.ComponentNameECKOperator,
				ResourceRequirements: &corev1.ResourceRequirements{
					Limits:   limits,
					Requests: requests,
				},
			},
		}
	}
}

func validateComponentResources(spec *operatorv1.LogStorageSpec) error {
	if spec.ComponentResources == nil {
		return fmt.Errorf("LogStorage spec.ComponentResources is nil %+v", spec)
	}
	// Currently the only supported component is ECKOperator.
	if len(spec.ComponentResources) > 1 {
		return fmt.Errorf("LogStorage spec.ComponentResources contains unsupported components %+v", spec.ComponentResources)
	}

	if spec.ComponentResources[0].ComponentName != operatorv1.ComponentNameECKOperator {
		return fmt.Errorf("LogStorage spec.ComponentResources.ComponentName %s is not supported", spec.ComponentResources[0].ComponentName)
	}

	return nil
}

func setLogStorageFinalizer(ls *operatorv1.LogStorage) {
	if ls.DeletionTimestamp == nil {
		if !stringsutil.StringInSlice(LogStorageFinalizer, ls.GetFinalizers()) {
			ls.SetFinalizers(append(ls.GetFinalizers(), LogStorageFinalizer))
		}
	}
}

func (r *LogStorageInitializer) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogStorage")

	ls := &operatorv1.LogStorage{}
	key := utils.DefaultTSEEInstanceKey
	if r.multiTenant {
		key.Namespace = request.Namespace
	}
	err := r.client.Get(ctx, key, ls)
	if errors.IsNotFound(err) {
		// Not finding the LogStorage CR is not an error, as a Managed cluster will not have this CR available but
		// there are still "LogStorage" related items that need to be set up
		ls = nil
		r.status.OnCRNotFound()
	} else if err != nil {
		// An actual error ocurred when attempting to query the LogStorage API.
		r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying LogStorage", err, reqLogger)
		return reconcile.Result{}, err
	} else {
		// We found the LogStorage instance.
		r.status.OnCRFound()

		// Create a snapshot of the pre-defaulting LogStorage state to use when performing a
		// merge patch to update the resource later.
		preDefaultingPatchFrom := client.MergeFrom(ls.DeepCopy())

		// Default and validate the object.
		fillDefaults(ls)
		err = validateComponentResources(&ls.Spec)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceValidationError, "An error occurred while validating LogStorage", err, reqLogger)
			return reconcile.Result{}, err
		}
		setLogStorageFinalizer(ls)

		// Write the logstorage back to the datastore with its newly applied defaults.
		if err = r.client.Patch(ctx, ls, preDefaultingPatchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourcePatchError, "Failed to write defaults", err, reqLogger)
			return reconcile.Result{}, err
		}
		defer r.status.SetMetaData(&ls.ObjectMeta)

		// Update the LogStorage status conditions with the conditions found on the TigeraStatus resource.
		// TODO: This should happen in the other sub controllers as well.
		if request.Name == ResourceName && request.Namespace == "" {
			ts := &operatorv1.TigeraStatus{}
			err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
			if err != nil {
				return reconcile.Result{}, err
			}
			ls.Status.Conditions = status.UpdateStatusCondition(ls.Status.Conditions, ts.Status.Conditions)
			if err := r.client.Status().Update(ctx, ls); err != nil {
				log.WithValues("reason", err).Info("Failed to create LogStorage status conditions.")
				return reconcile.Result{}, err
			}
		}
	}

	// Determine if we're terminating, and thus if we need to clean up our finalizers. We add a finalizer to the LogStorage
	// so that we can block deletion of it until downstream resources have termianted. Specifically, the Elasticsearch and Kibana
	// instances. So, check if those have been deleted before removing the finalizer.
	if ls != nil && ls.DeletionTimestamp != nil {
		prePatch := client.MergeFrom(ls.DeepCopy())

		// Get Installation resource.
		_, install, err := utils.GetInstallation(context.Background(), r.client)
		if err != nil {
			if errors.IsNotFound(err) {
				r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, reqLogger)
				return reconcile.Result{}, err
			}
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred while querying Installation", err, reqLogger)
			return reconcile.Result{}, err
		}

		// Check whether ES and Kibana CRs exist.
		elasticsearch, err := utils.GetElasticsearch(ctx, r.client)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Elasticsearch", err, reqLogger)
			return reconcile.Result{}, err
		}
		var kibana *kbv1.Kibana
		if !operatorv1.IsFIPSModeEnabled(install.FIPSMode) {
			err := r.client.Get(ctx, client.ObjectKey{Name: render.KibanaName, Namespace: render.KibanaNamespace}, kibana)
			if err != nil && !errors.IsNotFound(err) {
				r.status.SetDegraded(operatorv1.ResourceReadError, "An error occurred trying to retrieve Kibana", err, reqLogger)
				return reconcile.Result{}, err
			}
		}

		// Remove the finalizer if both ES and Kibana have been cleaned up.
		if elasticsearch == nil && kibana == nil {
			ls.SetFinalizers(stringsutil.RemoveStringInSlice(LogStorageFinalizer, ls.GetFinalizers()))

			// Write the logstorage back to the datastore
			if patchErr := r.client.Patch(ctx, ls, prePatch); patchErr != nil {
				reqLogger.Error(patchErr, "Error patching the log-storage")
				r.status.SetDegraded(operatorv1.ResourcePatchError, "Error patching the log-storage", patchErr, reqLogger)
				return reconcile.Result{}, patchErr
			}
		}
	}

	// Mark the status as available.
	r.status.ReadyToMonitor()
	r.status.ClearDegraded()

	// Since we don't poll for the object we need to make sure the object wouldn't have been deleted on the patch
	// that may have removed the finalizers.
	if ls != nil && (ls.DeletionTimestamp == nil || len(ls.GetFinalizers()) > 0) {
		ls.Status.State = operatorv1.TigeraStatusReady
		if err := r.client.Status().Update(ctx, ls); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, fmt.Sprintf("Error updating the log-storage status %s", operatorv1.TigeraStatusReady), err, reqLogger)
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}
