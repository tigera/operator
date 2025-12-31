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
	"fmt"
	"path"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/snowzach/rotatefilehook"
	"github.com/urfave/cli/v3"
)

func logPrettifier(f *runtime.Frame) (string, string) {
	filename := path.Base(f.File)
	funcSegments := strings.Split(f.Function, "/")
	return fmt.Sprintf("%s()", funcSegments[len(funcSegments)-1]), fmt.Sprintf("%s:%d", filename, f.Line)
}

// configureLogging sets up logging to both stdout and a file.
func configureLogging(c *cli.Command) {
	if debug := c.Bool(debugFlag.Name); debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	logrus.SetFormatter(&logrus.TextFormatter{
		DisableLevelTruncation: true,
		CallerPrettyfier:       logPrettifier,
		ForceColors:            true,
		PadLevelText:           true,
		DisableQuote:           true,
		DisableSorting:         true,
	})

	filename := strings.ReplaceAll(c.FullName(), " ", "-") + ".log"

	rotateFileHook, err := rotatefilehook.NewRotateFileHook(rotatefilehook.RotateFileConfig{
		Filename:   filename,
		MaxSize:    100,
		MaxAge:     30,
		MaxBackups: 10,
		Level:      logrus.DebugLevel,
		Formatter: &logrus.TextFormatter{
			DisableColors:          true,
			DisableLevelTruncation: true,
			CallerPrettyfier:       logPrettifier,
			DisableSorting:         true,
		},
	})
	if err != nil {
		cli.HandleExitCoder(cli.Exit(fmt.Errorf("unable to create logrus hook for log file rotation: %w", err), 1))
	}

	logrus.AddHook(rotateFileHook)
}
