package render

import (
	"github.com/tigera/operator/pkg/elasticsearch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Elasticsearch is a Component that contains the k8s resources required for another component to have elasticsearch access.
type elasticsearchUsers struct {
	users map[string]*elasticsearch.User
}

func ElasticsearchUsers(users map[string]*elasticsearch.User) Component {
	return &elasticsearchUsers{
		users: users,
	}
}

func (eu elasticsearchUsers) Objects() []runtime.Object {
	var objs []runtime.Object
	for secretName, user := range eu.users {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: ElasticsearchNamespace,
			},
			Data: map[string][]byte{
				"username": []byte(user.Username),
				"password": []byte(user.Password),
			},
		}
		objs = append(objs, secret)
	}

	return objs
}

func (eu elasticsearchUsers) Ready() bool {
	return true
}
