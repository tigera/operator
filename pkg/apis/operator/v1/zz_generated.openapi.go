// +build !ignore_autogenerated

// This file was autogenerated by openapi-gen. Do not edit it manually!

package v1

import (
	spec "github.com/go-openapi/spec"
	common "k8s.io/kube-openapi/pkg/common"
)

func GetOpenAPIDefinitions(ref common.ReferenceCallback) map[string]common.OpenAPIDefinition {
	return map[string]common.OpenAPIDefinition{
		"github.com/tigera/operator/pkg/apis/operator/v1.APIServer":                schema_pkg_apis_operator_v1_APIServer(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.APIServerSpec":            schema_pkg_apis_operator_v1_APIServerSpec(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.APIServerStatus":          schema_pkg_apis_operator_v1_APIServerStatus(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.Auth":                     schema_pkg_apis_operator_v1_Auth(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.Compliance":               schema_pkg_apis_operator_v1_Compliance(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.ComplianceSpec":           schema_pkg_apis_operator_v1_ComplianceSpec(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.ComplianceStatus":         schema_pkg_apis_operator_v1_ComplianceStatus(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.Installation":             schema_pkg_apis_operator_v1_Installation(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.InstallationSpec":         schema_pkg_apis_operator_v1_InstallationSpec(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.InstallationStatus":       schema_pkg_apis_operator_v1_InstallationStatus(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.IntrusionDetection":       schema_pkg_apis_operator_v1_IntrusionDetection(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.IntrusionDetectionSpec":   schema_pkg_apis_operator_v1_IntrusionDetectionSpec(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.IntrusionDetectionStatus": schema_pkg_apis_operator_v1_IntrusionDetectionStatus(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.LogCollector":             schema_pkg_apis_operator_v1_LogCollector(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.LogCollectorSpec":         schema_pkg_apis_operator_v1_LogCollectorSpec(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.LogCollectorStatus":       schema_pkg_apis_operator_v1_LogCollectorStatus(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.LogStorage":               schema_pkg_apis_operator_v1_LogStorage(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.LogStorageSpec":           schema_pkg_apis_operator_v1_LogStorageSpec(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.LogStorageStatus":         schema_pkg_apis_operator_v1_LogStorageStatus(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.Manager":                  schema_pkg_apis_operator_v1_Manager(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.ManagerSpec":              schema_pkg_apis_operator_v1_ManagerSpec(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.ManagerStatus":            schema_pkg_apis_operator_v1_ManagerStatus(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.S3StoreSpec":              schema_pkg_apis_operator_v1_S3StoreSpec(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.TigeraStatus":             schema_pkg_apis_operator_v1_TigeraStatus(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.TigeraStatusSpec":         schema_pkg_apis_operator_v1_TigeraStatusSpec(ref),
		"github.com/tigera/operator/pkg/apis/operator/v1.TigeraStatusStatus":       schema_pkg_apis_operator_v1_TigeraStatusStatus(ref),
	}
}

func schema_pkg_apis_operator_v1_APIServer(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "APIServer installs the Tigera API server and related resources. At most one instance of this resource is supported. It must be named \"tigera-secure\".",
				Properties: map[string]spec.Schema{
					"kind": {
						SchemaProps: spec.SchemaProps{
							Description: "Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"apiVersion": {
						SchemaProps: spec.SchemaProps{
							Description: "APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"metadata": {
						SchemaProps: spec.SchemaProps{
							Ref: ref("k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"),
						},
					},
					"spec": {
						SchemaProps: spec.SchemaProps{
							Description: "Specification of the desired state for the Tigera API server.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.APIServerSpec"),
						},
					},
					"status": {
						SchemaProps: spec.SchemaProps{
							Description: "Most recently observed status for the Tigera API server.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.APIServerStatus"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.APIServerSpec", "github.com/tigera/operator/pkg/apis/operator/v1.APIServerStatus", "k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"},
	}
}

func schema_pkg_apis_operator_v1_APIServerSpec(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "APIServerSpec defines the desired state of Tigera API server.",
				Properties:  map[string]spec.Schema{},
			},
		},
		Dependencies: []string{},
	}
}

func schema_pkg_apis_operator_v1_APIServerStatus(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "APIServerStatus defines the observed state of Tigera API server.",
				Properties: map[string]spec.Schema{
					"state": {
						SchemaProps: spec.SchemaProps{
							Description: "State provides user-readable status.",
							Type:        []string{"string"},
							Format:      "",
						},
					},
				},
			},
		},
		Dependencies: []string{},
	}
}

func schema_pkg_apis_operator_v1_Auth(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "Auth defines authentication configuration.",
				Properties: map[string]spec.Schema{
					"type": {
						SchemaProps: spec.SchemaProps{
							Description: "Type configures the type of authentication used by the manager. Default: Token",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"authority": {
						SchemaProps: spec.SchemaProps{
							Description: "Authority configures the OAuth2/OIDC authority/issuer when using OAuth2 or OIDC login.",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"clientID": {
						SchemaProps: spec.SchemaProps{
							Description: "ClientId configures the OAuth2/OIDC client ID to use for OAuth2 or OIDC login.",
							Type:        []string{"string"},
							Format:      "",
						},
					},
				},
			},
		},
		Dependencies: []string{},
	}
}

func schema_pkg_apis_operator_v1_Compliance(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "Compliance installs the components required for Tigera compliance reporting. At most one instance of this resource is supported. It must be named \"tigera-secure\".",
				Properties: map[string]spec.Schema{
					"kind": {
						SchemaProps: spec.SchemaProps{
							Description: "Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"apiVersion": {
						SchemaProps: spec.SchemaProps{
							Description: "APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"metadata": {
						SchemaProps: spec.SchemaProps{
							Ref: ref("k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"),
						},
					},
					"spec": {
						SchemaProps: spec.SchemaProps{
							Description: "Specification of the desired state for Tigera compliance reporting.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.ComplianceSpec"),
						},
					},
					"status": {
						SchemaProps: spec.SchemaProps{
							Description: "Most recently observed state for Tigera compliance reporting.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.ComplianceStatus"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.ComplianceSpec", "github.com/tigera/operator/pkg/apis/operator/v1.ComplianceStatus", "k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"},
	}
}

func schema_pkg_apis_operator_v1_ComplianceSpec(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "ComplianceSpec defines the desired state of Tigera compliance reporting capabilities.",
				Properties:  map[string]spec.Schema{},
			},
		},
		Dependencies: []string{},
	}
}

func schema_pkg_apis_operator_v1_ComplianceStatus(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "ComplianceStatus defines the observed state of Tigera compliance reporting capabilities.",
				Properties: map[string]spec.Schema{
					"state": {
						SchemaProps: spec.SchemaProps{
							Description: "State provides user-readable status.",
							Type:        []string{"string"},
							Format:      "",
						},
					},
				},
			},
		},
		Dependencies: []string{},
	}
}

func schema_pkg_apis_operator_v1_Installation(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "Installation configures an installation of Calico or Tigera Secure EE. At most one instance of this resource is supported. It must be named \"default\". The Installation API installs core networking and network policy components, and provides general install-time configuration.",
				Properties: map[string]spec.Schema{
					"kind": {
						SchemaProps: spec.SchemaProps{
							Description: "Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"apiVersion": {
						SchemaProps: spec.SchemaProps{
							Description: "APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"metadata": {
						SchemaProps: spec.SchemaProps{
							Ref: ref("k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"),
						},
					},
					"spec": {
						SchemaProps: spec.SchemaProps{
							Description: "Specification of the desired state for the Calico or Tigera Secure EE installation.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.InstallationSpec"),
						},
					},
					"status": {
						SchemaProps: spec.SchemaProps{
							Description: "Most recently observed state for the Calico or Tigera Secure EE installation.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.InstallationStatus"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.InstallationSpec", "github.com/tigera/operator/pkg/apis/operator/v1.InstallationStatus", "k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"},
	}
}

func schema_pkg_apis_operator_v1_InstallationSpec(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "InstallationSpec defines configuration for a Calico or Tigera Secure EE installation.",
				Properties: map[string]spec.Schema{
					"variant": {
						SchemaProps: spec.SchemaProps{
							Description: "Variant is the product to install - one of Calico or TigeraSecureEnterprise Default: Calico",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"registry": {
						SchemaProps: spec.SchemaProps{
							Description: "Registry is the default Docker registry used for component Docker images. If specified, all images will be pulled from this registry. If not specified then the default registries will be used. Image format:\n   <registry>/<imagePath>/<imageName>:<tag-name>\nThis option allows configuring the <registry> portion of the above format.",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"imagePath": {
						SchemaProps: spec.SchemaProps{
							Description: "ImagePath allows for the path part of an image to be specified. If specified then the specified value will be used as the image path for each image. If not specified or empty, the default for each image will be used. Image format:\n   <registry>/<imagePath>/<imageName>:<tag-name>\nThis option allows configuring the <imagePath> portion of the above format.",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"imagePullSecrets": {
						SchemaProps: spec.SchemaProps{
							Description: "ImagePullSecrets is an array of references to container registry pull secrets to use. These are applied to all images to be pulled.",
							Type:        []string{"array"},
							Items: &spec.SchemaOrArray{
								Schema: &spec.Schema{
									SchemaProps: spec.SchemaProps{
										Ref: ref("k8s.io/api/core/v1.LocalObjectReference"),
									},
								},
							},
						},
					},
					"kubernetesProvider": {
						SchemaProps: spec.SchemaProps{
							Description: "KubernetesProvider specifies a particular provider of the Kubernetes platform. This is often auto-detected. If specified, this enables provider-specific configuration and must match the auto-detected value (if any).",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"calicoNetwork": {
						SchemaProps: spec.SchemaProps{
							Description: "CalicoNetwork specifies configuration options for Calico provided pod networking.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.CalicoNetworkSpec"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.CalicoNetworkSpec", "k8s.io/api/core/v1.LocalObjectReference"},
	}
}

func schema_pkg_apis_operator_v1_InstallationStatus(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "InstallationStatus defines the observed state of the Calico or Tigera Secure installation.",
				Properties: map[string]spec.Schema{
					"variant": {
						SchemaProps: spec.SchemaProps{
							Description: "Variant is the most recently observed installed variant - one of Calico or TigeraSecureEnterprise",
							Type:        []string{"string"},
							Format:      "",
						},
					},
				},
			},
		},
		Dependencies: []string{},
	}
}

func schema_pkg_apis_operator_v1_IntrusionDetection(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "IntrusionDetection installs the components required for Tigera intrusion detection. At most one instance of this resource is supported. It must be named \"tigera-secure\".",
				Properties: map[string]spec.Schema{
					"kind": {
						SchemaProps: spec.SchemaProps{
							Description: "Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"apiVersion": {
						SchemaProps: spec.SchemaProps{
							Description: "APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"metadata": {
						SchemaProps: spec.SchemaProps{
							Ref: ref("k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"),
						},
					},
					"spec": {
						SchemaProps: spec.SchemaProps{
							Description: "Specification of the desired state for Tigera intrusion detection.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.IntrusionDetectionSpec"),
						},
					},
					"status": {
						SchemaProps: spec.SchemaProps{
							Description: "Most recently observed state for Tigera intrusion detection.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.IntrusionDetectionStatus"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.IntrusionDetectionSpec", "github.com/tigera/operator/pkg/apis/operator/v1.IntrusionDetectionStatus", "k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"},
	}
}

func schema_pkg_apis_operator_v1_IntrusionDetectionSpec(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "IntrusionDetectionSpec defines the desired state of Tigera intrusion detection capabilities.",
				Properties:  map[string]spec.Schema{},
			},
		},
		Dependencies: []string{},
	}
}

func schema_pkg_apis_operator_v1_IntrusionDetectionStatus(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "IntrusionDetectionStatus defines the observed state of Tigera intrusion detection capabilities.",
				Properties: map[string]spec.Schema{
					"state": {
						SchemaProps: spec.SchemaProps{
							Description: "State provides user-readable status.",
							Type:        []string{"string"},
							Format:      "",
						},
					},
				},
			},
		},
		Dependencies: []string{},
	}
}

func schema_pkg_apis_operator_v1_LogCollector(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "LogCollector installs the components required for Tigera flow and DNS log collection. At most one instance of this resource is supported. It must be named \"tigera-secure\". When created, this installs fluentd on all nodes configured to collect Tigera log data and export it to Tigera's Elasticsearch cluster as well as any additionally configured destinations.",
				Properties: map[string]spec.Schema{
					"kind": {
						SchemaProps: spec.SchemaProps{
							Description: "Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"apiVersion": {
						SchemaProps: spec.SchemaProps{
							Description: "APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"metadata": {
						SchemaProps: spec.SchemaProps{
							Ref: ref("k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"),
						},
					},
					"spec": {
						SchemaProps: spec.SchemaProps{
							Description: "Specification of the desired state for Tigera log collection.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.LogCollectorSpec"),
						},
					},
					"status": {
						SchemaProps: spec.SchemaProps{
							Description: "Most recently observed state for Tigera log collection.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.LogCollectorStatus"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.LogCollectorSpec", "github.com/tigera/operator/pkg/apis/operator/v1.LogCollectorStatus", "k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"},
	}
}

func schema_pkg_apis_operator_v1_LogCollectorSpec(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "LogCollectorSpec defines the desired state of Tigera flow, audit, and DNS log collection.",
				Properties: map[string]spec.Schema{
					"additionalStores": {
						SchemaProps: spec.SchemaProps{
							Description: "Configuration for exporting flow, audit, and DNS logs to external storage.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.AdditionalLogStoreSpec"),
						},
					},
					"additionalSources": {
						SchemaProps: spec.SchemaProps{
							Description: "Configuration for importing audit logs from managed kubernetes cluster log sources.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.AdditionalLogSourceSpec"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.AdditionalLogSourceSpec", "github.com/tigera/operator/pkg/apis/operator/v1.AdditionalLogStoreSpec"},
	}
}

func schema_pkg_apis_operator_v1_LogCollectorStatus(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "LogCollectorStatus defines the observed state of Tigera flow and DNS log collection",
				Properties: map[string]spec.Schema{
					"state": {
						SchemaProps: spec.SchemaProps{
							Description: "State provides user-readable status.",
							Type:        []string{"string"},
							Format:      "",
						},
					},
				},
			},
		},
		Dependencies: []string{},
	}
}

func schema_pkg_apis_operator_v1_LogStorage(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "LogStorage installs the components required for Tigera flow and DNS log storage. At most one instance of this resource is supported. It must be named \"tigera-secure\". When created, this installs an Elasticsearch cluster for use by Tigera Secure.",
				Properties: map[string]spec.Schema{
					"kind": {
						SchemaProps: spec.SchemaProps{
							Description: "Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"apiVersion": {
						SchemaProps: spec.SchemaProps{
							Description: "APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"metadata": {
						SchemaProps: spec.SchemaProps{
							Ref: ref("k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"),
						},
					},
					"spec": {
						SchemaProps: spec.SchemaProps{
							Description: "Specification of the desired state for Tigera log storage.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.LogStorageSpec"),
						},
					},
					"status": {
						SchemaProps: spec.SchemaProps{
							Description: "Most recently observed state for Tigera log storage.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.LogStorageStatus"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.LogStorageSpec", "github.com/tigera/operator/pkg/apis/operator/v1.LogStorageStatus", "k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"},
	}
}

func schema_pkg_apis_operator_v1_LogStorageSpec(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "LogStorageSpec defines the desired state of Tigera flow and DNS log storage.",
				Properties: map[string]spec.Schema{
					"nodes": {
						SchemaProps: spec.SchemaProps{
							Description: "Nodes defines the configuration for a set of identical Elasticsearch cluster nodes, each of type master, data, and ingest.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.Nodes"),
						},
					},
					"indices": {
						SchemaProps: spec.SchemaProps{
							Description: "Index defines the configuration for the indices in the Elasticsearch cluster.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.Indices"),
						},
					},
					"retention": {
						SchemaProps: spec.SchemaProps{
							Description: "Retention defines how long data is retained in the Elasticsearch cluster before it is cleared.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.Retention"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.Indices", "github.com/tigera/operator/pkg/apis/operator/v1.Nodes", "github.com/tigera/operator/pkg/apis/operator/v1.Retention"},
	}
}

func schema_pkg_apis_operator_v1_LogStorageStatus(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "LogStorageStatus defines the observed state of Tigera flow and DNS log storage.",
				Properties: map[string]spec.Schema{
					"state": {
						SchemaProps: spec.SchemaProps{
							Description: "State provides user-readable status.",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"elasticsearchHash": {
						SchemaProps: spec.SchemaProps{
							Description: "ElasticsearchHash represents the current revision and configuration of the installed Elasticsearch cluster. This is an opaque string which can be monitored for changes to perform actions when Elasticsearch is modified.",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"kibanaHash": {
						SchemaProps: spec.SchemaProps{
							Description: "KibanaHash represents the current revision and configuration of the installed Kibana dashboard. This is an opaque string which can be monitored for changes to perform actions when Kibana is modified.",
							Type:        []string{"string"},
							Format:      "",
						},
					},
				},
			},
		},
		Dependencies: []string{},
	}
}

func schema_pkg_apis_operator_v1_Manager(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "Manager installs the Tigera Secure manager graphical user interface. At most one instance of this resource is supported. It must be named \"tigera-secure\".",
				Properties: map[string]spec.Schema{
					"kind": {
						SchemaProps: spec.SchemaProps{
							Description: "Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"apiVersion": {
						SchemaProps: spec.SchemaProps{
							Description: "APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"metadata": {
						SchemaProps: spec.SchemaProps{
							Ref: ref("k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"),
						},
					},
					"spec": {
						SchemaProps: spec.SchemaProps{
							Description: "Specification of the desired state for the Tigera Secure EE manager.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.ManagerSpec"),
						},
					},
					"status": {
						SchemaProps: spec.SchemaProps{
							Description: "Most recently observed state for the Tigera Secure EE manager.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.ManagerStatus"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.ManagerSpec", "github.com/tigera/operator/pkg/apis/operator/v1.ManagerStatus", "k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"},
	}
}

func schema_pkg_apis_operator_v1_ManagerSpec(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "ManagerSpec defines configuration for the Tigera Secure manager GUI.",
				Properties: map[string]spec.Schema{
					"auth": {
						SchemaProps: spec.SchemaProps{
							Description: "Auth defines the authentication strategy for the Tigera Secure manager GUI.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.Auth"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.Auth"},
	}
}

func schema_pkg_apis_operator_v1_ManagerStatus(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "ManagerStatus defines the observed state of the Tigera Secure manager GUI.",
				Properties: map[string]spec.Schema{
					"auth": {
						SchemaProps: spec.SchemaProps{
							Description: "The last successfully applied authentication configuration.",
							Ref:         ref("github.com/tigera/operator/pkg/apis/operator/v1.Auth"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.Auth"},
	}
}

func schema_pkg_apis_operator_v1_S3StoreSpec(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "S3StoreSpec defines configuration for exporting logs to Amazon S3.",
				Properties: map[string]spec.Schema{
					"region": {
						SchemaProps: spec.SchemaProps{
							Description: "AWS Region of the S3 bucket",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"bucketName": {
						SchemaProps: spec.SchemaProps{
							Description: "Name of the S3 bucket to send logs",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"bucketPath": {
						SchemaProps: spec.SchemaProps{
							Description: "Path in the S3 bucket where to send logs",
							Type:        []string{"string"},
							Format:      "",
						},
					},
				},
				Required: []string{"region", "bucketName", "bucketPath"},
			},
		},
		Dependencies: []string{},
	}
}

func schema_pkg_apis_operator_v1_TigeraStatus(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "TigeraStatus represents the most recently observed status for Calico or a Tigera Secure EE functional area.",
				Properties: map[string]spec.Schema{
					"kind": {
						SchemaProps: spec.SchemaProps{
							Description: "Kind is a string value representing the REST resource this object represents. Servers may infer this from the endpoint the client submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"apiVersion": {
						SchemaProps: spec.SchemaProps{
							Description: "APIVersion defines the versioned schema of this representation of an object. Servers should convert recognized schemas to the latest internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources",
							Type:        []string{"string"},
							Format:      "",
						},
					},
					"metadata": {
						SchemaProps: spec.SchemaProps{
							Ref: ref("k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"),
						},
					},
					"spec": {
						SchemaProps: spec.SchemaProps{
							Ref: ref("github.com/tigera/operator/pkg/apis/operator/v1.TigeraStatusSpec"),
						},
					},
					"status": {
						SchemaProps: spec.SchemaProps{
							Ref: ref("github.com/tigera/operator/pkg/apis/operator/v1.TigeraStatusStatus"),
						},
					},
				},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.TigeraStatusSpec", "github.com/tigera/operator/pkg/apis/operator/v1.TigeraStatusStatus", "k8s.io/apimachinery/pkg/apis/meta/v1.ObjectMeta"},
	}
}

func schema_pkg_apis_operator_v1_TigeraStatusSpec(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Properties: map[string]spec.Schema{},
			},
		},
		Dependencies: []string{},
	}
}

func schema_pkg_apis_operator_v1_TigeraStatusStatus(ref common.ReferenceCallback) common.OpenAPIDefinition {
	return common.OpenAPIDefinition{
		Schema: spec.Schema{
			SchemaProps: spec.SchemaProps{
				Description: "TigeraStatusStatus defines the observed state of TigeraStatus",
				Properties: map[string]spec.Schema{
					"conditions": {
						SchemaProps: spec.SchemaProps{
							Description: "Conditions represents the latest observed set of conditions for this component. A component may be one or more of Available, Progressing, or Degraded.",
							Type:        []string{"array"},
							Items: &spec.SchemaOrArray{
								Schema: &spec.Schema{
									SchemaProps: spec.SchemaProps{
										Ref: ref("github.com/tigera/operator/pkg/apis/operator/v1.TigeraStatusCondition"),
									},
								},
							},
						},
					},
				},
				Required: []string{"conditions"},
			},
		},
		Dependencies: []string{
			"github.com/tigera/operator/pkg/apis/operator/v1.TigeraStatusCondition"},
	}
}
