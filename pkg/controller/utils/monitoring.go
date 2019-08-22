package utils

import (
	"context"
	"fmt"
	"strings"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"github.com/tigera/operator/pkg/render"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

// GetMonitoringConfig returns the default installation instance with defaults populated.
func GetMonitoringConfig(ctx context.Context, cli client.Client) (*operatorv1.MonitoringConfiguration, error) {
	instance := &operatorv1.MonitoringConfiguration{}
	err := cli.Get(ctx, DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}
	return populateMonitoringConfigDefaults(instance), nil
}

func populateMonitoringConfigDefaults(m *operatorv1.MonitoringConfiguration) *operatorv1.MonitoringConfiguration {
	if len(m.Spec.ClusterName) == 0 {
		m.Spec.ClusterName = "cluster"
	}
	return m
}

func AddMonitoringWatch(c controller.Controller) error {
	return c.Watch(&source.Kind{Type: &operatorv1.MonitoringConfiguration{}}, &handler.EnqueueRequestForObject{})
}

func ValidateMonitoringConfig(m *operatorv1.MonitoringConfiguration) error {
	errMsg := ""
	if m.Spec.ClusterName == "" {
		errMsg = "ClusterName not set"
	}
	if m.Spec.Elasticsearch == nil {
		errMsg = strings.Join([]string{errMsg, "Elasticsearch config not defined"}, ";")
	} else if m.Spec.Elasticsearch.Endpoint == "" {
		errMsg = strings.Join([]string{errMsg, "Elasticsearch Endpoint not defined"}, ";")
	} else if _, _, _, err := render.ParseEndpoint(m.Spec.Elasticsearch.Endpoint); err != nil {
		errMsg = strings.Join([]string{errMsg, "Elasticsearch Endpoint invalid"}, ";")
	}
	if m.Spec.Kibana == nil {
		errMsg = strings.Join([]string{errMsg, "Kibana config not defined"}, ";")
	} else if m.Spec.Kibana.Endpoint == "" {
		errMsg = strings.Join([]string{errMsg, "Kibana Endpoint not defined"}, ";")
	} else if _, _, _, err := render.ParseEndpoint(m.Spec.Kibana.Endpoint); err != nil {
		errMsg = strings.Join([]string{errMsg, "Kibana Endpoint invalid"}, ";")
	}

	if errMsg == "" {
		return nil
	}
	return fmt.Errorf(errMsg)
}
