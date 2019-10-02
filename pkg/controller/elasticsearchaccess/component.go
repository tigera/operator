package elasticsearchaccess

import (
	"fmt"
	"github.com/tigera/operator/pkg/elasticsearch"
)

type ElasticsearchComponentAccess struct {
	name  string
	roles []elasticsearch.Role
}

func (eca ElasticsearchComponentAccess) Name() string {
	return eca.name
}
func (eca ElasticsearchComponentAccess) Roles() []elasticsearch.Role {
	return eca.roles
}
func (eca ElasticsearchComponentAccess) SecretName() string {
	return ComponentSecretName(eca.name)
}

var elasticsearchComponentAccess = map[string]ElasticsearchComponentAccess{}

func AddComponent(componentName string, roles ...elasticsearch.Role) {
	elasticsearchComponentAccess[componentName] = ElasticsearchComponentAccess{
		name:  componentName,
		roles: roles,
	}
}

func GetComponents() []ElasticsearchComponentAccess {
	var cs []ElasticsearchComponentAccess
	for _, c := range elasticsearchComponentAccess {
		cs = append(cs, c)
	}
	return cs
}

func ComponentSecretName(componentName string) string {
	return fmt.Sprintf("%s-elasticsearch-access", componentName)
}
