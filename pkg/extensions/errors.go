// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package extensions

import (
	"errors"
	"fmt"
)

// ErrInvalidConfig marks configuration an extension does not support. Controllers
// match on it to degrade with a validation reason rather than a create reason.
var ErrInvalidConfig = errors.New("invalid configuration")

// InvalidConfigf returns an error that matches ErrInvalidConfig and reports the
// given message.
func InvalidConfigf(format string, args ...any) error {
	return invalidConfig{fmt.Errorf(format, args...)}
}

type invalidConfig struct {
	error
}

func (invalidConfig) Is(target error) bool {
	return target == ErrInvalidConfig
}

func (e invalidConfig) Unwrap() error {
	return e.error
}
