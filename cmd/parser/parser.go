package main

import (
	"context"
	"fmt"
	"log"

	operatorv1 "github.com/tigera/operator/pkg/apis/operator/v1"

	"github.com/tigera/operator/pkg/controller/migration/convert"
	"gopkg.in/yaml.v2"
	client "sigs.k8s.io/controller-runtime/pkg/client"

	appsv1 "k8s.io/api/apps/v1"

	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := appsv1.AddToScheme(scheme.Scheme); err != nil {
		return err
	}

	cl, err := client.New(config.GetConfigOrDie(), client.Options{})
	if err != nil {
		return err
	}

	var i = &operatorv1.Installation{}

	if err := convert.Convert(context.Background(), cl, i); err != nil {
		return err
	}
	if i == nil {
		return fmt.Errorf("no install detected")
	}

	bits, err := yaml.Marshal(i)
	if err != nil {
		return err
	}
	fmt.Println(string(bits))
	return nil
}
