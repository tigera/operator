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

package logcollector

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	operatorv1 "github.com/tigera/operator/api/v1"
	v1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/installation"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/render"
)

var log = logf.Log.WithName("controller_logcollector")

// Add creates a new LogCollector Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}
	return add(mgr, newReconciler(mgr, opts.DetectedProvider))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, provider operatorv1.Provider) reconcile.Reconciler {
	c := &ReconcileLogCollector{
		client:   mgr.GetClient(),
		scheme:   mgr.GetScheme(),
		provider: provider,
		status:   status.New(mgr.GetClient(), "log-collector"),
	}
	c.status.Run()
	return c
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("logcollector-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return fmt.Errorf("Failed to create logcollector-controller: %v", err)
	}

	// Watch for changes to primary resource LogCollector
	err = c.Watch(&source.Kind{Type: &operatorv1.LogCollector{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("logcollector-controller failed to watch primary resource: %v", err)
	}

	err = utils.AddAPIServerWatch(c)
	if err != nil {
		return fmt.Errorf("logcollector-controller failed to watch APIServer resource: %v", err)
	}

	for _, secretName := range []string{
		render.ElasticsearchLogCollectorUserSecret, render.ElasticsearchEksLogForwarderUserSecret,
		render.ElasticsearchPublicCertSecret, render.S3FluentdSecretName, render.EksLogForwarderSecret,
		render.SplunkFluentdTokenSecretName, render.SplunkFluentdCertificateSecretName} {
		if err = utils.AddSecretsWatch(c, secretName, render.OperatorNamespace()); err != nil {
			return fmt.Errorf("log-collector-controller failed to watch the Secret resource(%s): %v", secretName, err)
		}
	}

	for _, configMapName := range []string{render.FluentdFilterConfigMapName, render.ElasticsearchConfigMapName} {
		if err = utils.AddConfigMapWatch(c, configMapName, render.OperatorNamespace()); err != nil {
			return fmt.Errorf("logcollector-controller failed to watch ConfigMap %s: %v", configMapName, err)
		}
	}

	return nil
}

// blank assignment to verify that ReconcileLogCollector implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileLogCollector{}

// ReconcileLogCollector reconciles a LogCollector object
type ReconcileLogCollector struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client   client.Client
	scheme   *runtime.Scheme
	provider operatorv1.Provider
	status   status.StatusManager
}

// GetLogCollector returns the default LogCollector instance with defaults populated.
func GetLogCollector(ctx context.Context, cli client.Client) (*operatorv1.LogCollector, error) {
	// Fetch the instance. We only support a single instance named "tigera-secure".
	instance := &operatorv1.LogCollector{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	if instance.Spec.AdditionalStores != nil {
		if instance.Spec.AdditionalStores.Syslog != nil {
			_, _, _, err := render.ParseEndpoint(instance.Spec.AdditionalStores.Syslog.Endpoint)
			if err != nil {
				return nil, fmt.Errorf("Syslog config has invalid Endpoint: %s", err)
			}
		}
	}

	return instance, nil
}

// Reconcile reads that state of the cluster for a LogCollector object and makes changes based on the state read
// and what is in the LogCollector.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileLogCollector) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling LogCollector")
	ctx := context.Background()
	// Keep track of whether we changed the LogCollector instance during reconcile, so that we know to save it.
	isModified := false
	// Keep track of which fields were modified (helpful for error messages)
	modifiedFields := []string{}

	// Fetch the LogCollector instance
	instance, err := GetLogCollector(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			reqLogger.Info("LogCollector object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded("Error querying for LogCollector", err.Error())
		return reconcile.Result{}, err
	}
	reqLogger.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()

	if !utils.IsAPIServerReady(r.client, reqLogger) {
		r.status.SetDegraded("Waiting for Tigera API server to be ready", "")
		return reconcile.Result{}, nil
	}

	if err = utils.CheckLicenseKey(ctx, r.client); err != nil {
		r.status.SetDegraded("License not found", err.Error())
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Fetch the Installation instance. We need this for a few reasons.
	// - We need to make sure it has successfully completed installation.
	// - We need to get the registry information from its spec.
	installation, err := installation.GetInstallation(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded("Installation not found", err.Error())
			return reconcile.Result{}, err
		}
		r.status.SetDegraded("Error querying installation", err.Error())
		return reconcile.Result{}, err
	}

	esClusterConfig, err := utils.GetElasticsearchClusterConfig(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Elasticsearch cluster configuration is not available, waiting for it to become available")
			r.status.SetDegraded("Elasticsearch cluster configuration is not available, waiting for it to become available", err.Error())
			return reconcile.Result{}, nil
		}
		log.Error(err, "Failed to get the elasticsearch cluster configuration")
		r.status.SetDegraded("Failed to get the elasticsearch cluster configuration", err.Error())
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(installation, r.client)
	if err != nil {
		log.Error(err, "Error with Pull secrets")
		r.status.SetDegraded("Error retrieving pull secrets", err.Error())
		return reconcile.Result{}, err
	}

	esSecrets, err := utils.ElasticsearchSecrets(ctx, []string{render.ElasticsearchLogCollectorUserSecret, render.ElasticsearchEksLogForwarderUserSecret}, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("Elasticsearch secrets are not available yet, waiting until they become available")
			r.status.SetDegraded("Elasticsearch secrets are not available yet, waiting until they become available", err.Error())
			return reconcile.Result{RequeueAfter: 5 * time.Second}, nil
		}
		r.status.SetDegraded("Failed to get Elasticsearch credentials", err.Error())
		return reconcile.Result{}, err
	}

	var s3Credential *render.S3Credential
	if instance.Spec.AdditionalStores != nil {
		if instance.Spec.AdditionalStores.S3 != nil {
			s3Credential, err = getS3Credential(r.client)
			if err != nil {
				log.Error(err, "Error with S3 credential secret")
				r.status.SetDegraded("Error with S3 credential secret", err.Error())
				return reconcile.Result{}, err
			}
			if s3Credential == nil {
				log.Info("S3 credential secret does not exist")
				r.status.SetDegraded("S3 credential secret does not exist", "")
				return reconcile.Result{}, nil
			}
		}
	}

	var splunkCredential *render.SplunkCredential
	if instance.Spec.AdditionalStores != nil {
		if instance.Spec.AdditionalStores.Splunk != nil {
			splunkCredential, err = getSplunkCredential(r.client)
			if err != nil {
				log.Error(err, "Error with Splunk credential secret")
				r.status.SetDegraded("Error with Splunk credential secret", err.Error())
				return reconcile.Result{}, err
			}
			if splunkCredential == nil {
				log.Info("Splunk credential secret does not exist")
				r.status.SetDegraded("Splunk credential secret does not exist", "")
				return reconcile.Result{}, nil
			}
		}
	}

	if instance.Spec.AdditionalStores != nil {
		if instance.Spec.AdditionalStores.Syslog != nil {
			syslog := instance.Spec.AdditionalStores.Syslog

			// Try to grab the ManagementClusterConnection CR because we need it for some
			// validation with respect to Syslog.logTypes.
			managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
			if err != nil {
				// Not finding a ManagementClusterConnection CR is not an error, as only a managed cluster will
				// have this CR available, but we should communicate any other kind of error that we encounter.
				if !errors.IsNotFound(err) {
					r.status.SetDegraded(
						"An error occurred while looking for a ManagementClusterConnection",
						err.Error(),
					)
					return reconcile.Result{}, err
				}
			}

			// If the user set Syslog.logTypes, we need to ensure that they did not include
			// the v1.SyslogLogIDSEvents option if this is a managed cluster (i.e.
			// ManagementClusterConnection CR is present). This is because IDS events
			// are only forwarded within a non-managed cluster (where LogStorage is present).
			if syslog.LogTypes != nil {
				if err == nil && managementClusterConnection != nil {
					for _, l := range syslog.LogTypes {
						// Set status to degraded to warn user and let them fix the issue themselves.
						if l == v1.SyslogLogIDSEvents {
							r.status.SetDegraded(
								"IDSEvents option is not supported for Syslog config in a managed cluster",
								"",
							)
							return reconcile.Result{}, err
						}
					}
				}
			}

			// Special case: For users that have a Syslog config and are upgrading from an older release
			//  where logTypes field did not exist, we will auto-populate default values for
			// them. This should only happen on upgrade, since logTypes is a required field.
			if syslog.LogTypes == nil || len(syslog.LogTypes) == 0 {
				// Set default log types to everything except for v1.SyslogLogIDSEvents (since this
				// option was not available prior to the logTypes field being introduced). This ensures
				// existing users continue to get the same expected behavior for Syslog forwarding.
				instance.Spec.AdditionalStores.Syslog.LogTypes = []v1.SyslogLogType{
					v1.SyslogLogAudit,
					v1.SyslogLogDNS,
					v1.SyslogLogFlows,
				}

				// Mark LogCollector as changed so we know to save it
				isModified = true
				// Include the field that was modified (in case we need to display error messages)
				modifiedFields = append(modifiedFields, "AdditionalStores.Syslog.LogTypes")
			}
		}
	}

	filters, err := getFluentdFilters(r.client)
	if err != nil {
		log.Error(err, "Error retrieving Fluentd filters")
		r.status.SetDegraded("Error retrieving Fluentd filters", err.Error())
		return reconcile.Result{}, err
	}

	var eksConfig *render.EksCloudwatchLogConfig
	if installation.Spec.KubernetesProvider == operatorv1.ProviderEKS {
		log.Info("Managed kubernetes EKS found, getting necessary credentials and config")
		if instance.Spec.AdditionalSources != nil {
			if instance.Spec.AdditionalSources.EksCloudwatchLog != nil {
				eksConfig, err = getEksCloudwatchLogConfig(r.client,
					instance.Spec.AdditionalSources.EksCloudwatchLog.FetchInterval,
					instance.Spec.AdditionalSources.EksCloudwatchLog.Region,
					instance.Spec.AdditionalSources.EksCloudwatchLog.GroupName,
					instance.Spec.AdditionalSources.EksCloudwatchLog.StreamPrefix)
				if err != nil {
					log.Error(err, "Error retrieving EKS Cloudwatch Logs configuration")
					r.status.SetDegraded("Error retrieving EKS Cloudwatch Logs configuration", err.Error())
					return reconcile.Result{}, err
				}
			}
		}
	}

	// Update the LogCollector instance with any changes that have occurred.
	if isModified {
		if err = r.client.Update(ctx, instance); err != nil {
			r.status.SetDegraded(
				fmt.Sprintf(
					"Failed to set defaults for LogCollector fields: [%s]",
					strings.Join(modifiedFields, ", "),
				),
				err.Error(),
			)
			return reconcile.Result{}, err
		}
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, instance)

	// Render the desired objects from the CRD and create or update them.
	component := render.Fluentd(
		instance,
		esSecrets,
		esClusterConfig,
		s3Credential,
		splunkCredential,
		filters,
		eksConfig,
		pullSecrets,
		&installation.Spec,
	)

	if err := handler.CreateOrUpdate(ctx, component, r.status); err != nil {
		r.status.SetDegraded("Error creating / updating resource", err.Error())
		return reconcile.Result{}, err
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()

	if !r.status.IsAvailable() {
		// Schedule a kick to check again in the near future. Hopefully by then
		// things will be available.
		return reconcile.Result{RequeueAfter: 30 * time.Second}, nil
	}

	// Everything is available - update the CR status.
	instance.Status.State = operatorv1.TigeraStatusReady
	if err = r.client.Status().Update(ctx, instance); err != nil {
		return reconcile.Result{}, err
	}
	return reconcile.Result{}, nil
}

func getS3Credential(client client.Client) (*render.S3Credential, error) {
	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      render.S3FluentdSecretName,
		Namespace: render.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), secretNamespacedName, secret); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to read secret %q: %s", render.S3FluentdSecretName, err)
	}

	var ok bool
	var kId []byte
	if kId, ok = secret.Data[render.S3KeyIdName]; !ok || len(kId) == 0 {
		return nil, fmt.Errorf(
			"Expected secret %q to have a field named %q",
			render.S3FluentdSecretName, render.S3KeyIdName)
	}
	var kSecret []byte
	if kSecret, ok = secret.Data[render.S3KeySecretName]; !ok || len(kSecret) == 0 {
		return nil, fmt.Errorf(
			"Expected secret %q to have a field named %q",
			render.S3FluentdSecretName, render.S3KeySecretName)
	}

	return &render.S3Credential{
		KeyId:     kId,
		KeySecret: kSecret,
	}, nil
}

func getSplunkCredential(client client.Client) (*render.SplunkCredential, error) {
	tokenSecret := &corev1.Secret{}
	tokenNamespacedName := types.NamespacedName{
		Name:      render.SplunkFluentdTokenSecretName,
		Namespace: render.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), tokenNamespacedName, tokenSecret); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to read secret %q: %s", render.SplunkFluentdTokenSecretName, err)
	}

	var ok bool
	var token []byte
	if token, ok = tokenSecret.Data[render.SplunkFluentdSecretTokenKey]; !ok || len(token) == 0 {
		return nil, fmt.Errorf(
			"Expected secret %q to have a field named %q",
			render.SplunkFluentdTokenSecretName, render.SplunkFluentdSecretTokenKey)
	}

	var certificate []byte
	certificateSecret := &corev1.Secret{}
	certificateNamespacedName := types.NamespacedName{
		Name:      render.SplunkFluentdCertificateSecretName,
		Namespace: render.OperatorNamespace(),
	}

	if err := client.Get(context.Background(), certificateNamespacedName, certificateSecret); err != nil {
		if errors.IsNotFound(err) {
			log.Info(fmt.Sprintf("Splunk certificate secret %v not provided. Assuming http protocol or trusted CA certificate.",
				render.SplunkFluentdCertificateSecretName))
		} else {
			return nil, fmt.Errorf("Failed to read secret %q: %s", render.SplunkFluentdCertificateSecretName, err)
		}
	} else {
		if certificate, ok = certificateSecret.Data[render.SplunkFluentdSecretCertificateKey]; !ok || len(certificate) == 0 {
			return nil, fmt.Errorf("Expected secret %q to have a field named %q",
				render.SplunkFluentdCertificateSecretName, render.SplunkFluentdSecretCertificateKey)
		}
	}

	return &render.SplunkCredential{
		Token:       token,
		Certificate: certificate,
	}, nil
}

func getFluentdFilters(client client.Client) (*render.FluentdFilters, error) {
	cm := &corev1.ConfigMap{}
	cmNamespacedName := types.NamespacedName{
		Name:      render.FluentdFilterConfigMapName,
		Namespace: render.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), cmNamespacedName, cm); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to read ConfigMap %q: %s", render.FluentdFilterConfigMapName, err)
	}

	return &render.FluentdFilters{
		Flow: cm.Data[render.FluentdFilterFlowName],
		DNS:  cm.Data[render.FluentdFilterDNSName],
	}, nil
}

func getEksCloudwatchLogConfig(client client.Client, interval int32, region, group, prefix string) (*render.EksCloudwatchLogConfig, error) {
	if region == "" {
		return nil, fmt.Errorf("Missing AWS region info")
	}

	if group == "" {
		return nil, fmt.Errorf("Missing Cloudwatch log group name")
	}

	if prefix == "" {
		prefix = "kube-apiserver-audit-"
	}

	if interval == 0 {
		interval = 60
	}

	secret := &corev1.Secret{}
	secretNamespacedName := types.NamespacedName{
		Name:      render.EksLogForwarderSecret,
		Namespace: render.OperatorNamespace(),
	}
	if err := client.Get(context.Background(), secretNamespacedName, secret); err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to read Secret %q: %s", render.EksLogForwarderSecret, err)
	}

	if len(secret.Data[render.EksLogForwarderAwsId]) == 0 ||
		len(secret.Data[render.EksLogForwarderAwsKey]) == 0 {
		return nil, fmt.Errorf("Incomplete Cloudwatch credentials")
	}

	return &render.EksCloudwatchLogConfig{
		AwsId:         secret.Data[render.EksLogForwarderAwsId],
		AwsKey:        secret.Data[render.EksLogForwarderAwsKey],
		AwsRegion:     region,
		GroupName:     group,
		StreamPrefix:  prefix,
		FetchInterval: interval,
	}, nil
}
