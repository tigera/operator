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

package render_test

import (
	"github.com/tigera/operator/pkg/enterprise"
	"github.com/tigera/operator/pkg/extensions"
)

// ext is the enterprise extension Set the render suite tests against. The
// Objects()-level image tests pass ext.Images() into the node/windows configs to
// pick up the enterprise images, and the enterprise modifier tests apply ext's
// modifiers explicitly to real render output to check they still match it. It is
// immutable once built and specs only read it, so a single instance is safe.
var ext *extensions.Set = enterprise.New()
