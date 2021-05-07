package utils

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap"

	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/render"
	rauth "github.com/tigera/operator/pkg/render/common/authentication"
	keyvalidatorconfig "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetKeyValidatorConfig(ctx context.Context, cli client.Client, authenticationCR *operatorv1.Authentication, clusterDomain string) (rauth.KeyValidatorConfig, error) {
	var keyValidatorConfig rauth.KeyValidatorConfig
	if authenticationCR != nil {
		idpSecret, err := GetIdpSecret(ctx, cli, authenticationCR)
		if err != nil {
			return nil, err
		}

		oidc := authenticationCR.Spec.OIDC
		if authenticationCR.Spec.OIDC != nil && authenticationCR.Spec.OIDC.Type == operatorv1.OIDCTypeTigera {
			var kvcOptions []keyvalidatorconfig.Option

			if oidc.UsernameClaim != "" {
				kvcOptions = append(kvcOptions, keyvalidatorconfig.WithUsernameClaim(oidc.UsernameClaim))
			}
			if oidc.GroupsClaim != "" {
				kvcOptions = append(kvcOptions, keyvalidatorconfig.WithGroupsClaim(oidc.GroupsClaim))
			}
			if oidc.UsernamePrefix != "" {
				kvcOptions = append(kvcOptions, keyvalidatorconfig.WithUsernamePrefix(oidc.UsernamePrefix))
			}
			if oidc.GroupsPrefix != "" {
				kvcOptions = append(kvcOptions, keyvalidatorconfig.WithGroupsPrefix(oidc.GroupsPrefix))
			}

			keyValidatorConfig, err = keyvalidatorconfig.New(oidc.IssuerURL, string(idpSecret.Data["clientID"]), kvcOptions...)
			if err != nil {
				return nil, err
			}
		} else {
			dexTLSSecret := &corev1.Secret{}
			if err := cli.Get(ctx, types.NamespacedName{Name: render.DexCertSecretName, Namespace: rmeta.OperatorNamespace()}, dexTLSSecret); err != nil {
				return nil, err
			}

			keyValidatorConfig = render.NewDexKeyValidatorConfig(authenticationCR, idpSecret, dexTLSSecret, clusterDomain)
		}
	}

	return keyValidatorConfig, nil
}

func GetIdpSecret(ctx context.Context, client client.Client, authentication *operatorv1.Authentication) (*corev1.Secret, error) {
	var secretName string
	var requiredFields []string
	if authentication.Spec.OIDC != nil {
		secretName = render.OIDCSecretName
		requiredFields = append(requiredFields, render.ClientIDSecretField, render.ClientSecretSecretField)
	} else if authentication.Spec.Openshift != nil {
		secretName = render.OpenshiftSecretName
		requiredFields = append(requiredFields, render.ClientIDSecretField, render.ClientSecretSecretField, render.RootCASecretField)
	} else if authentication.Spec.LDAP != nil {
		secretName = render.LDAPSecretName
		requiredFields = append(requiredFields, render.BindDNSecretField, render.BindPWSecretField, render.RootCASecretField)
	}

	secret := &corev1.Secret{}
	if err := client.Get(ctx, types.NamespacedName{Name: secretName, Namespace: rmeta.OperatorNamespace()}, secret); err != nil {
		return nil, fmt.Errorf("missing secret %s/%s: %w", rmeta.OperatorNamespace(), secretName, err)
	}

	for _, field := range requiredFields {
		data := secret.Data[field]
		if len(data) == 0 {
			return nil, fmt.Errorf("%s is a required field for secret %s/%s", field, secret.Namespace, secret.Name)
		}

		if field == render.BindDNSecretField {
			if _, err := ldap.ParseDN(string(data)); err != nil {
				return nil, fmt.Errorf("secret %s/%s field %s: should have be a valid LDAP DN", rmeta.OperatorNamespace(), secretName, field)
			}
		}
	}
	return secret, nil
}
