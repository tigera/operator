package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"strings"
	"text/template"
	"unicode"
)

const (
	overrideTmplName     = "override.go.tpl"
	overrideTestTmplName = "override_test.go.tpl"
)

type override string

const (
	affinityOverride                  override = "affinityOverrideEnabled"
	tolerationsOverride               override = "tolerationsOverrideEnabled"
	nodeSelectorOverride              override = "nodeSelectorOverrideEnabled"
	resourcesOverride                 override = "resourcesOverrideEnabled"
	deploymentMetaDataOverride        override = "deploymentMetaDataOverrideEnabled"
	strategyOverride                  override = "strategyOverrideEnabled"
	podMetaDataOverride               override = "podMetaDataOverrideEnabled"
	podSecurityContextOverride        override = "podSecurityContextOverrideEnabled"
	securityContextOverride           override = "securityContextOverrideEnabled"
	priorityClassNameOverride         override = "priorityClassNameOverrideEnabled"
	topologySpreadConstraintsOverride override = "topologySpreadConstraintsOverrideEnabled"
)

var (
	allOverrides = []override{affinityOverride, tolerationsOverride, nodeSelectorOverride, resourcesOverride,
		deploymentMetaDataOverride, podMetaDataOverride, podSecurityContextOverride, securityContextOverride, priorityClassNameOverride,
		topologySpreadConstraintsOverride, strategyOverride}
)

var deployments = []deployment{
	{
		name:           "whisker",
		containerNames: []string{"whisker", "whisker-backend"},
		overrides:      allOverrides,
	},
	{
		name:           "goldmane",
		containerNames: []string{"goldmane"},
		overrides:      []override{resourcesOverride},
	},
}

type deployment struct {
	name           string
	containerNames []string
	overrides      []override
}

// TemplateData represents the data passed into the template
type TemplateData struct {
	Description    string
	Name           string
	StructPrefix   string
	ContainerNames []string
	Overrides      []override
}

func capitalizeUnicode(s string) string {
	if len(s) == 0 {
		return s
	}

	runes := []rune(s) // Convert string to runes to handle Unicode characters
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

func main() {
	for _, dep := range deployments {
		data := TemplateData{
			Description:    "Configuration for the Whisker Deployment Overrides",
			Name:           dep.name,
			StructPrefix:   capitalizeUnicode(dep.name),
			ContainerNames: dep.containerNames,
		}

		funcMap := template.FuncMap{
			"join": strings.Join,
			"asVarName": func(s string) string {
				return strings.ReplaceAll(strings.ToLower(s), "-", "")
			},
		}

		for _, o := range allOverrides {
			funcMap[string(o)] = func() bool {
				for _, overrid := range dep.overrides {
					if overrid == o {
						return true
					}
				}
				return false
			}
		}

		tmpl, err := template.New(overrideTmplName).
			Funcs(funcMap).
			ParseFiles("hack/gen-overrides/" + overrideTmplName)
		if err != nil {
			fmt.Println("Error parsing template:", err)
			os.Exit(1)
		}

		fileName := fmt.Sprintf("%s_deployment_types.go", dep.name)
		file, err := os.Create(fmt.Sprintf("api/v1/%s", fileName))
		if err != nil {
			fmt.Printf("Error creating file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		buf := bytes.NewBuffer(nil)
		// Execute the template
		err = tmpl.Execute(buf, data)
		if err != nil {
			fmt.Println("Error executing template:", err)
			os.Exit(1)
		}

		formatted, err := format.Source(buf.Bytes())
		if err != nil {
			// If there's an error, print it and exit
			panic(err)
		}

		if _, err := file.Write(formatted); err != nil {
			panic(err)
		}
		fmt.Printf("Successfully generated '%s'\n", fileName)

		generateTestFile(dep, funcMap)
	}
}

func generateTestFile(dep deployment, funcMap template.FuncMap) {
	data := TemplateData{
		Description:    "Configuration for the Whisker Deployment Overrides",
		Name:           dep.name,
		StructPrefix:   capitalizeUnicode(dep.name),
		ContainerNames: dep.containerNames,
	}

	tmpl, err := template.New(overrideTestTmplName).
		Funcs(funcMap).
		ParseFiles("hack/gen-overrides/" + overrideTestTmplName)
	if err != nil {
		fmt.Println("Error parsing template:", err)
		os.Exit(1)
	}

	fileName := "overrides_test.go"
	file, err := os.Create(fmt.Sprintf("pkg/render/%s/%s", dep.name, fileName))
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	buf := bytes.NewBuffer(nil)
	// Execute the template
	err = tmpl.Execute(buf, data)
	if err != nil {
		fmt.Println("Error executing template:", err)
		os.Exit(1)
	}

	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		// If there's an error, print it and exit
		panic(err)
	}

	if _, err := file.Write(formatted); err != nil {
		panic(err)
	}

	fmt.Printf("Successfully generated '%s'\n", fileName)
}
