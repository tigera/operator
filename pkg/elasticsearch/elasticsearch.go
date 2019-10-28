// This package is responsible for the communicating with elasticsearch, mainly transferring objects to requests to send
// to elasticsearch and parsing the responses from elasticsearch
package elasticsearch

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	es7 "github.com/elastic/go-elasticsearch/v7"
)

type Client struct {
	*es7.Client
}

// User represents an Elasticsearch user, which may or may not have roles attached to it
type User struct {
	Username string
	Password string
	Roles    []Role
}

// RoleNames is a convenience function for getting the names of all the roles defined for this Elasticsearch user
func (u User) RoleNames() []string {
	var names []string
	for _, role := range u.Roles {
		names = append(names, role.Name)
	}

	return names
}

// SecretName returns the name of the secret that should be used to store the information of this user
func (u User) SecretName() string {
	return fmt.Sprintf("%s-elasticsearch-access", u.Username)
}

// Role represents an Elasticsearch role that may be attached to a User
type Role struct {
	Name       string `json:"-"`
	Definition *RoleDefinition
}

type RoleDefinition struct {
	Cluster      []string      `json:"cluster"`
	Indices      []RoleIndex   `json:"indices"`
	Applications []Application `json:"applications,omitempty"`
}

type RoleIndex struct {
	Names      []string `json:"names"`
	Privileges []string `json:"privileges"`
}

type Application struct {
	Application string   `json:"application"`
	Privileges  []string `json:"privileges"`
	Resources   []string `json:"resources"`
}

func NewClient(url, username, password string, roots *x509.CertPool) (*Client, error) {
	config := es7.Config{
		Addresses: []string{
			url,
		},
		Username: username,
		Password: password,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: roots,
			},
		},
	}

	client, err := es7.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &Client{client}, nil
}

// createRoles wraps createRoles to make creating multiple rows slightly more convenient
func (cli Client) createRoles(roles ...Role) error {
	for _, role := range roles {
		if err := cli.createRole(role); err != nil {
			return err
		}
	}

	return nil
}

// createRole attempts to create (or updated) the given Elasticsearch role.
func (cli Client) createRole(role Role) error {
	j, err := json.Marshal(role.Definition)

	if role.Name == "" {
		return fmt.Errorf("can't create a role with an empty name")
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("_security/role/%s", role.Name), bytes.NewBuffer(j))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	response, err := cli.Perform(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf(string(body))
	}

	return nil
}

// CreateUser will create the Elasticsearch user and roles (if any roles are defined for the user). If the roles exist they
// will be updated.
func (cli Client) CreateUser(user User) error {
	var rolesToCreate []Role
	for _, role := range user.Roles {
		if role.Definition != nil {
			rolesToCreate = append(rolesToCreate, role)
		}
	}

	if len(rolesToCreate) > 0 {
		if err := cli.createRoles(rolesToCreate...); err != nil {
			return err
		}
	}

	j, err := json.Marshal(map[string]interface{}{
		"password": user.Password,
		"roles":    user.RoleNames(),
	})
	req, err := http.NewRequest("POST", fmt.Sprintf("_security/user/%s", user.Username), bytes.NewBuffer(j))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	response, err := cli.Perform(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf(string(body))
	}

	return nil
}

// UpdateUser will update the Elasticsearch users password and roles (if an roles are defined for the user). If the roles
// don't exist they will be created.
func (cli Client) UpdateUser(user User) error {
	var rolesToCreate []Role
	for _, role := range user.Roles {
		if role.Definition != nil {
			rolesToCreate = append(rolesToCreate, role)
		}
	}

	if len(rolesToCreate) > 0 {
		if err := cli.createRoles(rolesToCreate...); err != nil {
			return err
		}
	}

	j, err := json.Marshal(map[string]interface{}{
		"password": user.Password,
		"roles":    user.RoleNames(),
	})
	req, err := http.NewRequest("PUT", fmt.Sprintf("_security/user/%s", user.Username), bytes.NewBuffer(j))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	response, err := cli.Perform(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf(string(body))
	}

	return nil
}

// UserExists queries Elasticsearch to see if a user with the given username already exists
func (cli Client) UserExists(username string) (bool, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("_security/user/%s", username), nil)
	response, err := cli.Perform(req)
	if err != nil {
		return false, err
	}
	response.Body.Close()

	return response.StatusCode == 200, nil
}
