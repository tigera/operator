// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

// Component image variables
const (
	calicoRegistryConfigKey      = "CalicoRegistry"
	calicoImagePathConfigKey     = "CalicoImagePath"
	enterpriseRegistryConfigKey  = "TigeraRegistry"
	enterpriseImagePathConfigKey = "TigeraImagePath"
	operatorRegistryConfigKey    = "OperatorRegistry"
	operatorImagePathConfigKey   = "OperatorImagePath"
)

var componentImageConfigRelPath = "pkg/components/images.go"

// Mapping of component image keys to descriptions
var componentImageConfigMap = map[string]string{
	calicoRegistryConfigKey:      "Calico Registry",
	calicoImagePathConfigKey:     "Calico Image Path",
	enterpriseRegistryConfigKey:  "Enterprise Registry",
	enterpriseImagePathConfigKey: "Enterprise Image Path",
	operatorRegistryConfigKey:    "Operator Registry",
	operatorImagePathConfigKey:   "Operator Image Path",
}

// Build context keys
const (
	calicoBuildCtxKey     contextKey = "calico-build-type"
	enterpriseBuildCtxKey contextKey = "enterprise-build-type"
)

// Build types
const (
	versionsBuild buildType = "versions-file"
	versionBuild  buildType = "version"
)

// type of build being performed. Either using the Calico/Enterprise version or its corresponding versions file.
type buildType string

// Command to build release artifacts.
var buildCommand = &cli.Command{
	Name:  "build",
	Usage: "Build release artifacts",
	Flags: []cli.Flag{
		versionFlag,
		imageFlag,
		archFlag,
		registryFlag,
		calicoVersionFlag,
		calicoRegistryFlag,
		calicoImagePathFlag,
		calicoVersionsConfigFlag,
		calicoCRDsDirFlag,
		enterpriseVersionFlag,
		enterpriseRegistryFlag,
		enterpriseImagePathFlag,
		enterpriseVersionsConfigFlag,
		enterpriseCRDsDirFlag,
		hashreleaseFlag,
		skipValidationFlag,
	},
	Before: buildBefore,
	Action: buildAction,
}

// Pre-action for release build command.
var buildBefore = cli.BeforeFunc(func(ctx context.Context, c *cli.Command) (context.Context, error) {
	configureLogging(c)

	// Determine build types for Calico and Enterprise
	if ver := c.String(calicoVersionsConfigFlag.Name); ver != "" {
		ctx = context.WithValue(ctx, calicoBuildCtxKey, versionsBuild)
		logrus.Debug("Calico build using versions file selected")
	}
	if ver := c.String(calicoVersionFlag.Name); ver != "" {
		ctx = context.WithValue(ctx, calicoBuildCtxKey, versionBuild)
		logrus.Debug("Calico build using specific version selected")
	}
	if ver := c.String(enterpriseVersionsConfigFlag.Name); ver != "" {
		ctx = context.WithValue(ctx, enterpriseBuildCtxKey, versionsBuild)
		logrus.Debug("Enterprise build using versions file selected")
	}
	if ver := c.String(enterpriseVersionFlag.Name); ver != "" {
		ctx = context.WithValue(ctx, enterpriseBuildCtxKey, versionBuild)
		logrus.Debug("Enterprise build using specific version selected")
	}

	// Skip validations if requested
	if c.Bool(skipValidationFlag.Name) {
		logrus.Warnf("Skipping %s validation as requested.", c.Name)
		return ctx, nil
	}

	// Ensure that git working tree is clean
	ctx, err := checkGitClean(ctx)
	if err != nil {
		return ctx, err
	}

	isHashrelease := c.Bool(hashreleaseFlag.Name)

	// If not a hashrelease build, ensure version format is valid
	if valid, _ := isReleaseVersionFormat(c.String(versionFlag.Name)); !valid && !isHashrelease {
		return ctx, fmt.Errorf("for non-release builds, the %s flag must be set", hashreleaseFlag.Name)
	}

	// No further checks for release builds
	if !isHashrelease {
		return ctx, nil
	}

	// For hashrelease builds, ensure at least one of Calico or Enterprise version or versions file is specified.
	// If Calico/Enterprise version build is selected, ensure CRDs directory is specified
	// as the version will likely not exist as a tag/branch in the corresponding Calico/Enterprise repos.
	// If Calico/Enterprise is built using versions file, log a warning if CRDs directory is not specified.
	calicoBuildType, calicoBuildOk := ctx.Value(calicoBuildCtxKey).(buildType)
	enterpriseBuildType, enterpriseBuildOk := ctx.Value(enterpriseBuildCtxKey).(buildType)
	if !calicoBuildOk && !enterpriseBuildOk {
		return ctx, fmt.Errorf("for hashrelease builds, at least one of Calico or Enterprise version or versions file must be specified")
	}
	if calicoBuildOk {
		if calicoBuildType == versionBuild && c.String(calicoCRDsDirFlag.Name) == "" {
			return ctx, fmt.Errorf("Calico directory must be specified for hashrelease builds using calico-version flag")
		}
		if c.String(calicoCRDsDirFlag.Name) == "" {
			logrus.Warn("Calico directory not specified for hashrelease build, getting CRDs from default location may not be appropriate")
		}
	}
	if enterpriseBuildOk {
		if enterpriseBuildType == versionBuild && c.String(enterpriseCRDsDirFlag.Name) == "" {
			return ctx, fmt.Errorf("Enterprise directory must be specified for hashrelease builds using enterprise version")
		}
		if c.String(enterpriseCRDsDirFlag.Name) == "" {
			logrus.Warn("Enterprise directory not specified for hashrelease build, getting CRDs from default location may not be appropriate")
		}
	}

	return ctx, nil
})

// Action for release build command.
var buildAction = cli.ActionFunc(func(ctx context.Context, c *cli.Command) error {
	repoRootDir, err := gitDir()
	if err != nil {
		return fmt.Errorf("getting git directory: %w", err)
	}

	version := c.String(versionFlag.Name)
	log := logrus.WithField("version", version)

	// Prepare build environment variables
	buildEnv := append(os.Environ(), fmt.Sprintf("VERSION=%s", version))
	if arches := c.StringSlice(archFlag.Name); len(arches) > 0 {
		log = log.WithField("arches", arches)
		buildEnv = append(buildEnv, fmt.Sprintf("ARCHES=%s", strings.Join(arches, " ")))
	}
	if image := c.String(imageFlag.Name); image != defaultImageName {
		log = log.WithField("image", image)
		buildEnv = append(buildEnv,
			fmt.Sprintf("BUILD_IMAGE=%s", image),
			fmt.Sprintf("BUILD_INIT_IMAGE=%s-init", image))
	}
	if registry := c.String(registryFlag.Name); registry != "" && registry != quayRegistry {
		log = log.WithField("registry", registry)
		buildEnv = append(buildEnv,
			fmt.Sprintf("IMAGE_REGISTRY=%s", registry),
			fmt.Sprintf("PUSH_IMAGE_PREFIXES=%s", addTrailingSlash(registry)))
	}
	if c.Bool(hashreleaseFlag.Name) {
		log = log.WithField("hashrelease", true)
		buildEnv = append(buildEnv, fmt.Sprintf("GIT_VERSION=%s", c.String(versionFlag.Name)))
		resetFn, err := hashreleaseBuildConfig(ctx, c, repoRootDir)
		defer resetFn()
		if err != nil {
			return fmt.Errorf("preparing hashrelease build environment: %w", err)
		}
	} else {
		log = log.WithField("release", true)
		buildEnv = append(buildEnv, "RELEASE=true")
	}

	// Build the Operator and verify the build
	log.Info("Building Operator")
	if out, err := makeInDir(repoRootDir, "release-build", buildEnv...); err != nil {
		log.Error(out)
		return fmt.Errorf("building Operator: %w", err)
	}

	return nil
})

func hashreleaseBuildConfig(ctx context.Context, c *cli.Command, repoRootDir string) (func(), error) {
	repoReset := func() {
		if out, err := gitInDir(repoRootDir, append([]string{"checkout", "-f"}, changedFiles...)...); err != nil {
			logrus.WithError(err).Errorf("resetting git state: %s", out)
		}
	}
	image := c.String(imageFlag.Name)
	if image != defaultImageName {
		imageParts := strings.SplitN(c.String(imageFlag.Name), "/", 2)
		if err := modifyComponentImageConfig(repoRootDir, operatorImagePathConfigKey, addTrailingSlash(imageParts[0])); err != nil {
			return repoReset, fmt.Errorf("updating Operator image path: %w", err)
		}
	}
	registry := c.String(registryFlag.Name)
	if registry != "" && registry != quayRegistry {
		if err := modifyComponentImageConfig(repoRootDir, operatorRegistryConfigKey, addTrailingSlash(registry)); err != nil {
			return repoReset, fmt.Errorf("updating Operator registry: %w", err)
		}
	}
	if registry := c.String(calicoRegistryFlag.Name); registry != "" {
		if err := modifyComponentImageConfig(repoRootDir, calicoRegistryConfigKey, addTrailingSlash(registry)); err != nil {
			return repoReset, fmt.Errorf("updating Calico registry: %w", err)
		}
	}
	if imagePath := c.String(calicoImagePathFlag.Name); imagePath != "" {
		if err := modifyComponentImageConfig(repoRootDir, calicoImagePathConfigKey, imagePath); err != nil {
			return repoReset, fmt.Errorf("updating Calico image path: %w", err)
		}
	}
	if registry := c.String(enterpriseRegistryFlag.Name); registry != "" {
		if err := modifyComponentImageConfig(repoRootDir, enterpriseRegistryConfigKey, addTrailingSlash(registry)); err != nil {
			return repoReset, fmt.Errorf("updating Enterprise registry: %w", err)
		}
	}
	if imagePath := c.String(enterpriseImagePathFlag.Name); imagePath != "" {
		if err := modifyComponentImageConfig(repoRootDir, enterpriseImagePathConfigKey, imagePath); err != nil {
			return repoReset, fmt.Errorf("updating Enterprise image path: %w", err)
		}
	}

	// Update versions and CRDs
	genEnv := os.Environ()
	genMakeTargets := []string{}
	if dir := c.String(calicoCRDsDirFlag.Name); dir != "" {
		genEnv = append(genEnv, fmt.Sprintf("CALICO_CRDS_DIR=%s", dir))
	}
	if dir := c.String(enterpriseCRDsDirFlag.Name); dir != "" {
		genEnv = append(genEnv, fmt.Sprintf("ENTERPRISE_CRDS_DIR=%s", dir))
	}
	if bt, ok := ctx.Value(calicoBuildCtxKey).(buildType); ok {
		genMakeTargets = append(genMakeTargets, "gen-versions-calico")
		switch bt {
		case versionBuild:
			if err := updateConfigVersions(repoRootDir, calicoConfig, c.String(calicoVersionFlag.Name)); err != nil {
				return repoReset, fmt.Errorf("updating Calico config versions: %w", err)
			}
		case versionsBuild:
			genEnv = append(genEnv, fmt.Sprintf("OS_VERSIONS=%s", c.String(calicoVersionsConfigFlag.Name)))
		}
	}
	if bt, ok := ctx.Value(enterpriseBuildCtxKey).(buildType); ok {
		genMakeTargets = append(genMakeTargets, "gen-versions-enterprise")
		switch bt {
		case versionBuild:
			if err := updateConfigVersions(repoRootDir, enterpriseConfig, c.String(enterpriseVersionFlag.Name)); err != nil {
				return repoReset, fmt.Errorf("updating Enterprise config versions: %w", err)
			}
		case versionsBuild:
			genEnv = append(genEnv, fmt.Sprintf("EE_VERSIONS=%s", c.String(enterpriseVersionsConfigFlag.Name)))
		}
	}
	if out, err := makeInDir(repoRootDir, strings.Join(genMakeTargets, " "), genEnv...); err != nil {
		logrus.Error(out)
		return repoReset, fmt.Errorf("generating versions: %w", err)
	}
	return repoReset, nil
}

// Modify variables in pkg/components/images.go
func modifyComponentImageConfig(repoRootDir, configKey, newValue string) error {
	// Check the configKey is valid
	desc, ok := componentImageConfigMap[configKey]
	if !ok {
		return fmt.Errorf("invalid component image config key: %s", configKey)
	}

	logrus.WithField("repoDir", repoRootDir).WithField(configKey, newValue).Infof("Updating %s in %s", desc, componentImageConfigRelPath)

	if out, err := runCommandInDir(repoRootDir, "sed", []string{"-i", fmt.Sprintf(`s|%[1]s.*=.*".*"|%[1]s = "%[2]s"|`, configKey, regexp.QuoteMeta(newValue)), componentImageConfigRelPath}, nil); err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to update %s in %s: %w", desc, componentImageConfigRelPath, err)
	}
	return nil
}
