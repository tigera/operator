package elasticsearch

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	es7 "github.com/elastic/go-elasticsearch/v7"
)

type Client struct {
	*es7.Client
}

type User struct {
	Username string
	Password string
}

type Role struct {
	Name    string      `json:"-"`
	Cluster []string    `json:"cluster"`
	Indices []RoleIndex `json:"indices"`
}

type RoleIndex struct {
	Names      []string `json:"names"`
	Privileges []string `json:"privileges"`
}

func NewClient(url, username, password string, insecure bool) (*Client, error) {
	config := es7.Config{
		Addresses: []string{
			url,
		},
		Username: username,
		Password: password,
	}

	if insecure {
		config.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	client, err := es7.NewClient(config)
	if err != nil {
		return nil, err
	}

	return &Client{client}, nil
}

func (cli Client) CreateRoles(roles ...Role) error {
	for _, role := range roles {
		if err := cli.createRole(role); err != nil {
			return err
		}
	}

	return nil
}

func (cli Client) createRole(role Role) error {
	j, err := json.Marshal(role)

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
	} else if response.StatusCode != 200 {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf(string(body))
	}

	return nil
}

func (cli Client) CreateUser(username string, password string, roles []string) (*User, error) {
	j, err := json.Marshal(map[string]interface{}{
		"password": password,
		"roles":    roles,
	})
	req, err := http.NewRequest("POST", fmt.Sprintf("_security/user/%s", username), bytes.NewBuffer(j))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	response, err := cli.Perform(req)
	if err != nil {
		return nil, err
	} else if response.StatusCode != 200 {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(string(body))
	}

	return &User{Username: username, Password: password}, nil
}

func (cli Client) UpdateUser(username string, password string, roles []string) (*User, error) {
	j, err := json.Marshal(map[string]interface{}{
		"password": password,
		"roles":    roles,
	})
	req, err := http.NewRequest("PUT", fmt.Sprintf("_security/user/%s", username), bytes.NewBuffer(j))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	response, err := cli.Perform(req)
	if err != nil {
		return nil, err
	} else if response.StatusCode != 200 {
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf(string(body))
	}

	return &User{Username: username, Password: password}, nil
}

func (cli Client) UserExists(username string) (bool, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("_security/user/%s", username), nil)
	response, err := cli.Perform(req)
	if err != nil {
		return false, err
	}

	return response.StatusCode == 200, nil
}
