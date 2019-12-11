// This file contains multi cluster management specific functions to prevent the controllers from getting bloated.
package utils

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/tigera/operator/pkg/render"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetManagementClusterURL(voltronAddr string) (*url.URL, error) {
	if voltronAddr == "" {
		return nil, fmt.Errorf("ManagementClusterAddr is a required field for clusters of type 'management'")
	}
	uri, err := url.Parse(voltronAddr)
	if err != nil || uri.Host == "" {
		// this may be an ip, so let'voltronAddr try the network path reference notation: https://github.com/golang/go/issues/18824

		uri, err = url.Parse(fmt.Sprintf("tcp://%v", voltronAddr))
		if err != nil {
			return nil, fmt.Errorf("invalid value for field ManagementClusterAddr: unable to parse ")
		}
	}
	if uri.Scheme != "tcp" && uri.Scheme != "" {
		return nil, fmt.Errorf("invalid value for field ManagementClusterAddr: invalid scheme")
	}
	if uri.Port() == "" {
		return nil, fmt.Errorf("invalid value for field ManagementClusterAddr: port must not be specified")
	}
	if p, err := strconv.Atoi(uri.Port()); err != nil || p < 1 || p > 65535 {
		return nil, fmt.Errorf("invalid value for field ManagementClusterAddr: invalid port")
	}
	if uri.Hostname() == "" {
		return nil, fmt.Errorf("invalid value for field ManagementClusterAddr: invalid hostname")
	}
	if uri.User != nil {
		return nil, fmt.Errorf("invalid value for field ManagementClusterAddr: user should be omitted")
	}
	return uri, nil
}

// Guardian is picky about the url we supply it. It must be in the format "example.com:12", "1.2.3.4:12" or "[::1]:12"
func FormatManagementClusterURL(uri *url.URL) string {
	if uri == nil {
		return ""
	}
	return strings.TrimPrefix(uri.String(), "tcp://")
}

// If a cluster is no longer of type management, there are resources that should be cleaned up
func CleanUpMcm(ctx context.Context, cli client.Client) error {
	// Remove the unnecessary service if there is one
	svc := &corev1.Service{}
	err := cli.Get(ctx, client.ObjectKey{Name: render.VoltronName, Namespace: render.ManagerNamespace}, svc)
	found := true
	if err != nil {
		if errors.IsNotFound(err) {
			found = false
		} else {
			return err
		}
	}
	if found {
		err = cli.Delete(ctx, svc)
		if err != nil {
			return err
		}
	}
	// Remove unnecessary secret if there is one
	sec := &corev1.Secret{}
	err = cli.Get(ctx, client.ObjectKey{Name: render.VoltronTunnelSecretName, Namespace: render.ManagerNamespace}, sec)
	found = true
	if err != nil {
		if errors.IsNotFound(err) {
			found = false
		} else {
			return err
		}
	}
	if found {
		return cli.Delete(ctx, sec)
	}
	return nil
}

// The user can provide a secret for setting up the tunnel. If it does, we copy it over to the manager namespace,
// otherwise, we proceed and create a new secret. Returns the secret if applicable.
func CopyTunnelSecret(config *operatorv1.MulticlusterConfig, ctx context.Context, cli client.Client) (*corev1.Secret, error) {
	if config == nil || config.Spec.ClusterManagementType != operatorv1.ClusterManagementTypeManagement {
		// nothing to copy
		return nil, nil
	}
	oprSec, oprSecFound, err := getTunnelSecret(ctx, cli, render.OperatorNamespace())
	if err != nil {
		return nil, err
	}

	mgrSec, mgrSecFound, err := getTunnelSecret(ctx, cli, render.ManagerNamespace)
	if err != nil {
		return nil, err
	}

	if !oprSecFound {
		if !mgrSecFound {
			// No secrets are found in either namespace, so there is nothing to do here.
			return nil, nil
		} else {
			// There is a secret in the manager namespace, so we return it.
			return mgrSec, nil
		}
	}

	// Copy over the secret data to the manager secret.
	mgrSec.Data = oprSec.Data

	if !mgrSecFound {
		mgrSec.Name = render.VoltronTunnelSecretName
		mgrSec.Namespace = render.ManagerNamespace
		return mgrSec, cli.Create(ctx, mgrSec)
	}
	return mgrSec, cli.Update(ctx, mgrSec)
}

func getTunnelSecret(ctx context.Context, cli client.Client, ns string) (*corev1.Secret, bool, error) {
	secret := &corev1.Secret{}
	err := cli.Get(ctx, client.ObjectKey{Name: render.VoltronTunnelSecretName, Namespace: ns}, secret)
	if err != nil {
		if errors.IsNotFound(err) {
			return secret, false, nil
		}
		return nil, false, err
	}
	return secret, true, nil
}
