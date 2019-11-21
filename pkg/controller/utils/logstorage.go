package utils

import (
	"context"
	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetLogStorage returns the LogStorage resource as the first return value if, and only if, it exists, it is "ready", and
// no error occurred, otherwise the first return value will be nil. If an error occurred it will be return as the second
// return value
func GetReadyLogStorage(ctx context.Context, cli client.Client) (*operatorv1.LogStorage, error) {
	instance, err := GetLogStorage(ctx, cli)
	if err != nil {
		return nil, err
	}

	if instance.Status.State != operatorv1.LogStorageStatusReady {
		return nil, nil
	}

	fillDefaults(instance)

	return instance, nil
}

func GetLogStorage(ctx context.Context, cli client.Client) (*operatorv1.LogStorage, error) {
	instance := &operatorv1.LogStorage{}
	err := cli.Get(ctx, DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}

	fillDefaults(instance)

	return instance, nil
}

func fillDefaults(opr *operatorv1.LogStorage) {
	if opr.Spec.Retention == nil {
		opr.Spec.Retention = &operatorv1.Retention{}
	}

	if opr.Spec.Retention.Flows == nil {
		var fr int32 = 8
		opr.Spec.Retention.Flows = &fr
	}
	if opr.Spec.Retention.AuditReports == nil {
		var arr int32 = 365
		opr.Spec.Retention.AuditReports = &arr
	}
	if opr.Spec.Retention.Snapshots == nil {
		var sr int32 = 365
		opr.Spec.Retention.Snapshots = &sr
	}
	if opr.Spec.Retention.ComplianceReports == nil {
		var crr int32 = 365
		opr.Spec.Retention.ComplianceReports = &crr
	}

	if opr.Spec.Indices == nil {
		opr.Spec.Indices = &operatorv1.Indices{}
	}

	if opr.Spec.Indices.Replicas == nil {
		var replicas int32 = 0
		opr.Spec.Indices.Replicas = &replicas
	}
}
