package elasticsearchaccess

import "fmt"

type ElasticsearchComponentAccess struct {
	name  string
	roles []string
}

func (eca ElasticsearchComponentAccess) Name() string {
	return eca.name
}
func (eca ElasticsearchComponentAccess) Roles() []string {
	return eca.roles
}
func (eca ElasticsearchComponentAccess) SecretName() string {
	return ComponentSecretName(eca.name)
}

var elasticsearchComponentAccess = map[string]ElasticsearchComponentAccess{}

func AddComponent(componentName string, roles []string) {
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
