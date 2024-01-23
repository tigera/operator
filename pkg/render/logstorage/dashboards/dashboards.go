// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package dashboards

import (
	"fmt"
	"strings"

	rcomponents "github.com/tigera/operator/pkg/render/common/components"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/ptr"
	"github.com/tigera/operator/pkg/render"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/common/podsecuritypolicy"
	"github.com/tigera/operator/pkg/render/common/secret"
	"github.com/tigera/operator/pkg/render/common/securitycontext"
	"github.com/tigera/operator/pkg/render/logstorage"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	Name                     = "dashboards-installer"
	ElasticCredentialsSecret = "tigera-ee-dashboards-installer-elasticsearch-user-secret"
	PolicyName               = networkpolicy.TigeraComponentPolicyPrefix + Name
)

func Dashboards(c *Config) render.Component {
	return &dashboards{
		cfg: c,
	}
}

type dashboards struct {
	image    string
	csrImage string
	cfg      *Config
}

// Config contains all the information needed to render the Dashboards component.
type Config struct {
	// CustomResources provided by the user.
	Installation *operatorv1.InstallationSpec

	// Pull secrets provided by the user.
	PullSecrets []*corev1.Secret

	// Trusted bundle to use when validating client certificates.
	TrustedBundle certificatemanagement.TrustedBundleRO

	// Whether this is a managed cluster
	IsManaged bool

	// Whether the cluster supports pod security policies.
	UsePSP bool

	// Namespace to install into.
	Namespace string

	// Tenant configuration, if running for a particular tenant.
	Tenant *operatorv1.Tenant

	// Secret containing client certificate and key for connecting to the Kibana. If configured,
	// mTLS is used between Dashboards and the external Kibana.
	ExternalKibanaClientSecret *corev1.Secret

	// Kibana service definition
	KibanaHost   string
	KibanaPort   string
	KibanaScheme string

	// Credentials are used to provide annotations for elastic search users
	Credentials []*corev1.Secret
}

func (d *dashboards) ResolveImages(is *operatorv1.ImageSet) error {
	reg := d.cfg.Installation.Registry
	path := d.cfg.Installation.ImagePath
	prefix := d.cfg.Installation.ImagePrefix
	var err error
	errMsgs := []string{}

	// Calculate the image(s) to use for Dashboards, given user registry configuration.
	d.image, err = components.GetReference(components.ComponentElasticTseeInstaller, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if d.cfg.Installation.CertificateManagement != nil {
		d.csrImage, err = certificatemanagement.ResolveCSRInitImage(d.cfg.Installation, is)
		if err != nil {
			errMsgs = append(errMsgs, err.Error())
		}
	}
	if len(errMsgs) != 0 {
		return fmt.Errorf(strings.Join(errMsgs, ","))
	}
	return nil
}

func (d *dashboards) Objects() (objsToCreate, objsToDelete []client.Object) {
	if d.cfg.IsManaged || operatorv1.IsFIPSModeEnabled(d.cfg.Installation.FIPSMode) {
		return nil, d.resources()
	}

	return d.resources(), nil
}

func (d *dashboards) resources() []client.Object {
	resources := []client.Object{
		d.AllowTigeraPolicy(),
		d.ServiceAccount(),
		d.Job(),
	}

	if d.cfg.UsePSP {
		resources = append(resources,
			d.PSPClusterRole(),
			d.PSPClusterRoleBinding(),
			d.PodSecurityPolicy(),
		)
	}
	return resources
}

func (d *dashboards) AllowTigeraPolicy() *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, d.cfg.Installation.KubernetesProvider == operatorv1.ProviderOpenShift)
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: render.KibanaEntityRule,
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      PolicyName,
			Namespace: d.cfg.Namespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: fmt.Sprintf("job-name == '%s'", Name),
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}

func (d *dashboards) Job() *batchv1.Job {
	annotations := d.cfg.TrustedBundle.HashAnnotations()
	if d.cfg.ExternalKibanaClientSecret != nil {
		annotations["hash.operator.tigera.io/kibana-client-secret"] = rmeta.SecretsAnnotationHash(d.cfg.ExternalKibanaClientSecret)
	}

	volumeMounts := d.cfg.TrustedBundle.VolumeMounts(d.SupportedOSType())

	volumes := []corev1.Volume{
		d.cfg.TrustedBundle.Volume(),
	}

	secretName := ElasticCredentialsSecret

	envVars := []corev1.EnvVar{
		{
			Name:  "KIBANA_HOST",
			Value: d.cfg.KibanaHost,
		},
		{
			Name:  "KIBANA_PORT",
			Value: d.cfg.KibanaPort,
		},
		{
			Name:  "KIBANA_SCHEME",
			Value: d.cfg.KibanaScheme,
		},
		{
			// We no longer need to start the xpack trial from the installer pod. Logstorage
			// now takes care of this in combination with the ECK operator (v1).
			Name:  "START_XPACK_TRIAL",
			Value: "false",
		},
		{
			Name:      "USER",
			ValueFrom: secret.GetEnvVarSource(secretName, "username", false),
		},
		{
			Name:      "PASSWORD",
			ValueFrom: secret.GetEnvVarSource(secretName, "password", false),
		},
		{
			Name:  "KB_CA_CERT",
			Value: d.cfg.TrustedBundle.MountPath(),
		},
		{
			Name:  "FIPS_MODE_ENABLED",
			Value: operatorv1.IsFIPSModeEnabledString(d.cfg.Installation.FIPSMode),
		},
		relasticsearch.ElasticUserEnvVar(ElasticCredentialsSecret),
		relasticsearch.ElasticPasswordEnvVar(ElasticCredentialsSecret),
	}

	if d.cfg.Tenant != nil {
		envVars = append(envVars, corev1.EnvVar{
			Name:  "KIBANA_SPACE_ID",
			Value: d.cfg.Tenant.Spec.ID,
		})
	}

	if d.cfg.ExternalKibanaClientSecret != nil {
		// Add a volume for the required client certificate and key.
		volumes = append(volumes, corev1.Volume{
			Name: logstorage.ExternalCertsVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: logstorage.ExternalCertsSecret,
				},
			},
		})
		volumeMounts = append(volumeMounts, corev1.VolumeMount{
			Name:      logstorage.ExternalCertsVolumeName,
			MountPath: "/certs/kibana/mtls",
			ReadOnly:  true,
		})

		// Configure Dashboards to use the mounted client certificate and key.
		envVars = append(envVars, corev1.EnvVar{Name: "KIBANA_MTLS_ENABLED", Value: "true"})
		envVars = append(envVars, corev1.EnvVar{Name: "KIBANA_CLIENT_KEY", Value: "/certs/kibana/mtls/client.key"})
		envVars = append(envVars, corev1.EnvVar{Name: "KIBANA_CLIENT_CERT", Value: "/certs/kibana/mtls/client.crt"})
	}

	podTemplate := relasticsearch.DecorateAnnotations(&corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels:      map[string]string{"job-name": Name, "k8s-app": Name},
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			Tolerations:  d.cfg.Installation.ControlPlaneTolerations,
			NodeSelector: d.cfg.Installation.ControlPlaneNodeSelector,
			// This value needs to be set to never. The PodFailurePolicy will still ensure that this job will run until completion.
			RestartPolicy:    corev1.RestartPolicyNever,
			ImagePullSecrets: secret.GetReferenceList(d.cfg.PullSecrets),
			Containers: []corev1.Container{
				{
					Name:            Name,
					Image:           d.image,
					ImagePullPolicy: render.ImagePullPolicy(),
					Env:             envVars,
					SecurityContext: securitycontext.NewNonRootContext(),
					VolumeMounts:    volumeMounts,
				},
			},
			Volumes:            volumes,
			ServiceAccountName: Name,
		},
	}, d.cfg.Credentials).(*corev1.PodTemplateSpec)

	job := &batchv1.Job{
		TypeMeta: metav1.TypeMeta{Kind: "Job", APIVersion: "batch/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      Name,
			Namespace: d.cfg.Namespace,
		},
		Spec: batchv1.JobSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"job-name": Name,
				},
			},
			Template: *podTemplate,
			// PodFailurePolicy is not available for k8s < 1.26; setting BackoffLimit to a higher number (default is 6)
			// to lessen the frequency of installation failures when responses from Elastic Search takes more time.
			BackoffLimit: ptr.Int32ToPtr(30),
			PodFailurePolicy: &batchv1.PodFailurePolicy{
				Rules: []batchv1.PodFailurePolicyRule{
					// We don't want the job to fail, so we keep retrying by ignoring incrementing the backoff.
					{
						Action: "Ignore",
						OnExitCodes: &batchv1.PodFailurePolicyOnExitCodesRequirement{
							Operator: "NotIn",
							Values:   []int32{0},
						},
					},
				},
			},
		},
	}

	if d.cfg.Tenant != nil && d.cfg.Tenant.Spec.DashboardsJob != nil {
		if overrides := d.cfg.Tenant.Spec.DashboardsJob; overrides != nil {
			rcomponents.ApplyJobOverrides(job, overrides)
		}
	}

	return job
}

func (d *dashboards) ServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{Kind: "ServiceAccount", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      Name,
			Namespace: d.cfg.Namespace,
		},
	}
}

func (d *dashboards) PSPClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRole", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: Name,
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Allow access to the pod security policy in case this is enforced on the cluster
				APIGroups:     []string{"policy"},
				Resources:     []string{"podsecuritypolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{Name},
			},
		},
	}
}

func (d *dashboards) PSPClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleBinding", APIVersion: "rbac.authorization.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: Name,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      Name,
				Namespace: d.cfg.Namespace,
			},
		},
	}
}

func (d *dashboards) PodSecurityPolicy() *policyv1beta1.PodSecurityPolicy {
	return podsecuritypolicy.NewBasePolicy(Name)
}

func (d *dashboards) Ready() bool {
	return true
}

func (d *dashboards) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}
