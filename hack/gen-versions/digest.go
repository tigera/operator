package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

var gcrBearer = ""

var client = &http.Client{
	Timeout: 5 * time.Second,
}

// updateDigests updates a set of Components to include a 'digest' field.
// Components which do not specify a registry are assigned the defaultReg as per
// the versions.yml spec.
func updateDigests(cs Components, defaultReg string) error {
	for key, component := range cs {
		var registry = defaultReg
		if component.Registry != "" {
			registry = component.Registry
		}

		digest, err := getDigest(registry, component.Image, component.Version)
		if err != nil {
			return fmt.Errorf("failed to get digest for '%s/%s:%s': %v", registry, component.Image, component.Version, err)
		}

		cs[key].Digest = digest

		log.Println(digest)
	}

	return nil
}

func getDigest(registry, img, version string) (string, error) {
	registryURL := generateURL(registry, img, version)
	if registryURL == "" {
		return "", fmt.Errorf("failed to generate url for %s/%s:%s", registry, img, version)
	}
	log.Println(registryURL)
	r, _ := http.NewRequest(http.MethodGet, registryURL, nil)

	// handle authorization
	if strings.HasPrefix(registry, "gcr.io") {
		r.Header.Add("Authorization", "Bearer "+gcrBearer)
	}
	if strings.HasPrefix(registry, "docker.elastic.co") {
		resp, err := client.Get("https://docker-auth.elastic.co/auth?service=token-service&scope=repository:" + img + ":pull")
		if err != nil {
			return "", fmt.Errorf("could not get elastic auth")
		}
		body, _ := ioutil.ReadAll(resp.Body)
		var data = map[string]string{}
		json.Unmarshal(body, &data)

		elasticBearer := data["token"]
		r.Header.Add("Authorization", "Bearer "+elasticBearer)
	}
	if strings.HasPrefix(registry, "docker.io") {
		resp, err := client.Get("https://auth.docker.io/token?service=registry.docker.io&scope=repository:" + img + ":pull")
		if err != nil {
			return "", fmt.Errorf("could not get elastic auth")
		}
		body, _ := ioutil.ReadAll(resp.Body)
		var data = map[string]string{}
		json.Unmarshal(body, &data)

		bearer := data["token"]
		r.Header.Add("Authorization", "Bearer "+bearer)
	}

	resp, err := client.Do(r)
	if err != nil {
		return "", fmt.Errorf("failed to look up '%s/%s:%s': %v", registry, img, version, err)
	}

	digest := resp.Header.Get("docker-content-digest")
	if digest == "" {
		// grab body for debugging
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("no digest header in response. Error code: %d. URL: %s", resp.StatusCode, string(body))
	}

	return digest, nil
}

// generateURL produces an https URL for any given image registry.
func generateURL(registry, image, version string) string {
	// handle references to docker.io registry which is actually a dns alias for
	// registry-1.docker.io.
	registry = strings.Replace(registry, "docker.io", "registry-1.docker.io", 1)
	// for registries that contain more than just the domain (e.g. gcr.io/myproject/prefix),
	// split the url so that only the domain name appears before the /v2, and the rest appears after.
	r := strings.Split(registry, "/")
	u, _ := url.Parse(fmt.Sprintf("https://%s/v2/", r[0]))
	u.Path = path.Join(u.Path, strings.Join(r[1:], "/"), image, "/manifests", version)
	return u.String()
}
