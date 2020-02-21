// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

// The code in this file manages logstorage for any cluster that isn't of type "Managed". It handles the creation of
// Elasticsearch and Kibana.
package logstorage

import (
	"context"
	"fmt"
	"time"

	cmnv1 "github.com/elastic/cloud-on-k8s/pkg/apis/common/v1"
	esv1 "github.com/elastic/cloud-on-k8s/pkg/apis/elasticsearch/v1"
	kbv1 "github.com/elastic/cloud-on-k8s/pkg/apis/kibana/v1"
	"github.com/elastic/cloud-on-k8s/pkg/utils/stringsutil"
	"github.com/go-logr/logr"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	finalizer                  = "tigera.io/eck-cleanup"
	defaultElasticsearchShards = 5
)

// reconileUnManaged creates Elasticsearch and Kibana based off the configuration in the LogStorage CR.
func (r *ReconcileLogStorage) reconcileUnmanaged(ctx context.Context, network *operatorv1.Installation, reqLogger logr.Logger) (reconcile.Result, error) {
	ls, err := GetLogStorage(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("LogStorage resource not found", "")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Failed to get LogStorage CR", err.Error())
		return reconcile.Result{}, err
	}

	reqLogger.V(2).Info("Loaded config", "config", ls)
	r.status.OnCRFound()

	if ls.DeletionTimestamp != nil {
		return r.finalizeDeletion(ctx, ls)
	}

	if svc, err := r.getElasticsearchService(ctx); err == nil {
		// if the Elasticsearch service is an ExternalName service, then this was previous a "Managed" cluster and
		// the service needs to be removed before creating the Elasticsearch resource
		if svc.Spec.Type == corev1.ServiceTypeExternalName {
			if err := r.client.Delete(ctx, svc); err != nil {
				r.status.SetDegraded("Failed to delete external service", err.Error())
				return reconcile.Result{}, err
			}
		}
	} else if !errors.IsNotFound(err) {
		r.status.SetDegraded("Failed to retrieve external service", err.Error())
		return reconcile.Result{}, err
	}

	if !stringsutil.StringInSlice(finalizer, ls.GetFinalizers()) {
		ls.SetFinalizers(append(ls.GetFinalizers(), finalizer))
	}

	// Write back the LogStorage object to update any defaults that were set
	if err = r.client.Update(ctx, ls); err != nil {
		r.status.SetDegraded("Failed to update LogStorage with defaults", err.Error())
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(network, r.client)
	if err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Error retrieving pull secrets", err)
		return reconcile.Result{}, err
	}

	if err := r.client.Get(ctx, client.ObjectKey{Name: render.ElasticsearchStorageClass}, &storagev1.StorageClass{}); err != nil {
		r.setDegraded(ctx, reqLogger, ls, fmt.Sprintf("Couldn't find storage class %s, this must be provided", render.ElasticsearchStorageClass), err)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	esCertSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.TigeraElasticsearchCertSecret, Namespace: render.OperatorNamespace()}, esCertSecret); err != nil {
		if errors.IsNotFound(err) {
			esCertSecret = nil
		} else {
			r.setDegraded(ctx, reqLogger, ls, "Failed to read Elasticsearch cert secret", err)
			return reconcile.Result{}, err
		}
	}

	kibanaCertSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.TigeraKibanaCertSecret, Namespace: render.OperatorNamespace()}, kibanaCertSecret); err != nil {
		if errors.IsNotFound(err) {
			kibanaCertSecret = nil
		} else {
			r.setDegraded(ctx, reqLogger, ls, "Failed to read Kibana cert secret", err)
			return reconcile.Result{}, err
		}
	}

	// The ECK operator requires that we provide it with a secret so it can add certificate information in for its webhooks.
	// If it's created we don't want to overwrite it as we'll lose the certificate information the ECK operator relies on.
	createWebhookSecret := false
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ECKWebhookSecretName, Namespace: render.ECKOperatorNamespace}, &corev1.Secret{}); err != nil {
		if errors.IsNotFound(err) {
			createWebhookSecret = true
		} else {
			r.setDegraded(ctx, reqLogger, ls, "Failed to read Elasticsearch webhook secret", err)
			return reconcile.Result{}, err
		}
	}

	esClusterConfig := render.NewElasticsearchClusterConfig("cluster", ls.Replicas(), defaultElasticsearchShards)

	reqLogger.V(2).Info("Creating Elasticsearch components")
	hdler := utils.NewComponentHandler(log, r.client, r.scheme, ls)
	component, err := render.Elasticsearch(
		ls,
		esClusterConfig,
		esCertSecret,
		kibanaCertSecret,
		createWebhookSecret,
		pullSecrets,
		r.provider,
		network.Spec.Registry,
	)
	if err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Error rendering LogStorage", err)
		return reconcile.Result{}, err
	}

	if err := hdler.CreateOrUpdate(ctx, component, r.status); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Error creating / updating resource", err)
		return reconcile.Result{}, err
	}

	reqLogger.V(2).Info("Checking if Elasticsearch is operational")
	if isReady, err := r.isElasticsearchReady(ctx); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Error figuring out if Elasticsearch is operational", err)
		return reconcile.Result{}, err
	} else if !isReady {
		r.setDegraded(ctx, reqLogger, ls, "Waiting for Elasticsearch cluster to be operational", nil)
		return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
	}

	reqLogger.V(2).Info("Checking if Kibana is operational")
	if isReady, err := r.isKibanaReady(ctx); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Failed to figure out if Kibana is operational", err)
		return reconcile.Result{}, err
	} else if !isReady {
		r.setDegraded(ctx, reqLogger, ls, "Waiting for Kibana to be operational", nil)
		return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
	}

	reqLogger.V(2).Info("Elasticsearch and Kibana are operational")
	esPublicCertSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.ElasticsearchPublicCertSecret, Namespace: render.ElasticsearchNamespace}, esPublicCertSecret); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Failed to read Elasticsearch public cert secret", err)
		return reconcile.Result{}, err
	}

	kibanaPublicCertSecret := &corev1.Secret{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: render.KibanaPublicCertSecret, Namespace: render.KibanaNamespace}, kibanaPublicCertSecret); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Failed to read Kibana public cert secret", err)
		return reconcile.Result{}, err
	}

	if err := hdler.CreateOrUpdate(ctx, render.ElasticsearchSecrets(esPublicCertSecret, kibanaPublicCertSecret), r.status); err != nil {
		r.setDegraded(ctx, reqLogger, ls, "Error creating / update resource", err)
		return reconcile.Result{}, err
	}

	esSecrets, err := utils.ElasticsearchSecrets(context.Background(), []string{render.ElasticsearchCuratorUserSecret}, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Elasticsearch secrets are not available yet, waiting until they become available")
			r.status.SetDegraded("Elasticsearch secrets are not available yet, waiting until they become available", err.Error())
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Failed to get Elasticsearch credentials", err.Error())
		return reconcile.Result{}, err
	}

	curatorComponent := render.ElasticCurator(*ls, esSecrets, pullSecrets, network.Spec.Registry, render.DefaultElasticsearchClusterName)
	if err := hdler.CreateOrUpdate(ctx, curatorComponent, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	r.status.AddCronJobs([]types.NamespacedName{{Name: render.EsCuratorName, Namespace: render.ElasticsearchNamespace}})

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	reqLogger.V(2).Info("Elasticsearch users and secrets created for components needing Elasticsearch access")
	if err := r.updateStatus(ctx, reqLogger, ls, operatorv1.LogStorageStatusReady); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *ReconcileLogStorage) getElasticsearch(ctx context.Context) (*esv1.Elasticsearch, error) {
	es := esv1.Elasticsearch{}
	return &es, r.client.Get(ctx, client.ObjectKey{Name: render.ElasticsearchName, Namespace: render.ElasticsearchNamespace}, &es)
}

func (r *ReconcileLogStorage) getElasticsearchService(ctx context.Context) (*corev1.Service, error) {
	svc := corev1.Service{}
	return &svc, r.client.Get(ctx, client.ObjectKey{Name: render.ElasticsearchServiceName, Namespace: render.ElasticsearchNamespace}, &svc)
}

func (r *ReconcileLogStorage) getKibana(ctx context.Context) (*kbv1.Kibana, error) {
	kb := kbv1.Kibana{}
	return &kb, r.client.Get(ctx, client.ObjectKey{Name: render.KibanaName, Namespace: render.KibanaNamespace}, &kb)
}

func (r *ReconcileLogStorage) isElasticsearchReady(ctx context.Context) (bool, error) {
	if es, err := r.getElasticsearch(ctx); err != nil {
		return false, err
	} else if es.Status.Phase == esv1.ElasticsearchReadyPhase {
		return true, nil
	}

	return false, nil
}

func (r *ReconcileLogStorage) isKibanaReady(ctx context.Context) (bool, error) {
	if kb, err := r.getKibana(ctx); err != nil {
		return false, err
	} else if kb.Status.AssociationStatus == cmnv1.AssociationEstablished {
		return true, nil
	}

	return false, nil
}

// finalizeDeletion makes sure that both Kibana and Elasticsearch are deleted before removing the finalizers on the LogStorage
// resource. This needs to happen because the eck operator will be deleted when the LogStorage resource is deleted, but
// the eck operator is needed to delete Elasticsearch and Kibana
func (r *ReconcileLogStorage) finalizeDeletion(ctx context.Context, ls *operatorv1.LogStorage) (reconcile.Result, error) {
	// remove Elasticsearch
	if es, err := r.getElasticsearch(ctx); err == nil {
		if err := r.client.Delete(ctx, es); err != nil {
			r.status.SetDegraded("Failed to delete Elasticsearch", err.Error())
			return reconcile.Result{}, err
		}
	} else if !errors.IsNotFound(err) {
		return reconcile.Result{}, err
	}

	// remove kibana
	if kb, err := r.getKibana(ctx); err == nil {
		if err := r.client.Delete(ctx, kb); err != nil {
			r.status.SetDegraded("Failed to delete kibana", err.Error())
			return reconcile.Result{}, err
		}
	} else if !errors.IsNotFound(err) {
		return reconcile.Result{}, err
	}

	// remove the finalizer now that Elasticsearch and Kibana have been deleted
	ls.SetFinalizers(stringsutil.RemoveStringInSlice(finalizer, ls.GetFinalizers()))
	if err := r.client.Update(ctx, ls); err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}
