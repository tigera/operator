package cloudconfig

import (
	"fmt"
	"strconv"

	rmeta "github.com/tigera/operator/pkg/render/common/meta"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	CloudConfigConfigMapName = "tigera-secure-cloud-config"
)

func NewCloudConfig(tenantId string, tenantName string, externalESDomain string, externalKibanaDomain string, enableMTLS bool, useCA bool) *CloudConfig {
	return &CloudConfig{
		tenantId:             tenantId,
		tenantName:           tenantName,
		externalESDomain:     externalESDomain,
		externalKibanaDomain: externalKibanaDomain,
		enableMTLS:           enableMTLS,
		useCA:                useCA,
	}
}

func NewCloudConfigFromConfigMap(configMap *corev1.ConfigMap) (*CloudConfig, error) {
	var enableMTLS, useCA bool
	var err error

	if configMap.Data["tenantId"] == "" {
		return nil, fmt.Errorf("'tenantId' is not set")
	}

	if configMap.Data["tenantName"] == "" {
		return nil, fmt.Errorf("'tenantName' is not set")
	}

	if configMap.Data["externalESDomain"] == "" {
		return nil, fmt.Errorf("'externalESDomain' is not set")
	}

	if configMap.Data["externalKibanaDomain"] == "" {
		return nil, fmt.Errorf("'externalKibanaDomain' is not set")
	}

	if configMap.Data["enableMTLS"] == "" {
		enableMTLS = false
	} else {
		if enableMTLS, err = strconv.ParseBool(configMap.Data["enableMTLS"]); err != nil {
			return nil, errors.Wrap(err, "'enableMTLS' must be a bool")
		}
	}

	if configMap.Data["useCA"] == "" {
		useCA = false
	} else {
		if useCA, err = strconv.ParseBool(configMap.Data["useCA"]); err != nil {
			return nil, errors.Wrap(err, "'useCA' must be a bool")
		}
	}

	return NewCloudConfig(configMap.Data["tenantId"], configMap.Data["tenantName"], configMap.Data["externalESDomain"], configMap.Data["externalKibanaDomain"], enableMTLS, useCA), nil
}

type CloudConfig struct {
	tenantId             string
	tenantName           string
	externalESDomain     string
	externalKibanaDomain string
	enableMTLS           bool
	useCA                bool
}

func (c CloudConfig) TenantId() string {
	return c.tenantId
}

func (c CloudConfig) TenantName() string {
	return c.tenantName
}

func (c CloudConfig) ExternalESDomain() string {
	return c.externalESDomain
}

func (c CloudConfig) ExternalKibanaDomain() string {
	return c.externalKibanaDomain
}

func (c CloudConfig) EnableMTLS() bool {
	return c.enableMTLS
}

func (c CloudConfig) UseCA() bool {
	return c.useCA
}

func (c CloudConfig) ConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CloudConfigConfigMapName,
			Namespace: rmeta.OperatorNamespace(),
		},
		Data: map[string]string{
			"tenantId":             c.tenantId,
			"tenantName":           c.tenantName,
			"externalESDomain":     c.externalESDomain,
			"externalKibanaDomain": c.externalKibanaDomain,
			"enableMTLS":           strconv.FormatBool(c.enableMTLS),
			"useCA":                strconv.FormatBool(c.useCA),
		},
	}
}
