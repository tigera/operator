// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package elasticsearch

import "fmt"

func (c *ClusterConfig) AddTenantId(tenantId string) {
	c.clusterName = fmt.Sprintf("%s.%s", tenantId, c.clusterName)
}
