// This package provides a uniform way creating, managing, and sharing elasticsearch users between controllers that need
// require an elasticsearch user for access to elasticsearch and the logic that will create those users.
// Here's an example of how it's used at the time of writing this documentation:
//
// Any component that needs an elasticsearch user will call users.AddUser with the elasticsearch user they want to create
// for themselves. This could be done in the package's init function, but doesn't have to be (this just ensures that all
// the users to create are registered before the logic that creates those users runs). Here is an example of what the log-collector controller does:
//
// func init() {
// 	 esusers.AddUser(elasticsearch.User{
// 		 Username: render.ElasticsearchUserLogCollector,
// 		 Roles: []elasticsearch.Role{{
//			 Name:    render.ElasticsearchUserLogCollector,
//			 Cluster: []string{"monitor", "manage_index_templates"},
//			 Indices: []elasticsearch.RoleIndex{{
//				 Names:      []string{"tigera_secure_ee_*"},
//				 Privileges: []string{"create_index", "write"},
//			 }},
//		 }},
//	 })
// }
//
// The log-storage controller then creates all the users / roles that have been registered here by calling the esusers.GetUsers
// function, once the elasticsearch cluster is operational, and puts those users in secrets (using the UserSecretName function
// to get the secret name each user created).
//
// After the log-storage controller creates these secrets, the controller needing elasticsearch access will be watching
// for the secret that the log-storage controller is supposed to create, and now that it's created, it can copy over that.
// secret to it's namespace and user the Elasticsearch user credentials stored there to gain access to the Elasticsearch
// cluster.

package users

import (
	"fmt"
	"github.com/tigera/operator/pkg/elasticsearch"
)

var elasticsearchUsers = map[string]elasticsearch.User{}

func AddUser(user elasticsearch.User) {
	elasticsearchUsers[user.Username] = user
}

func GetUsers() []elasticsearch.User {
	var cs []elasticsearch.User
	for _, c := range elasticsearchUsers {
		cs = append(cs, c)
	}
	return cs
}

func GetUser(username string) (*elasticsearch.User, error) {
	if user, exists := elasticsearchUsers[username]; !exists {
		return nil, fmt.Errorf("Elasticsearch user %s hasn't been registered with AddUser", username)
	} else {
		return &user, nil
	}
}
