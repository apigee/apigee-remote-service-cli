// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutil

import (
	"strings"
	"testing"
)

// ErrorContains checks if the error string contains the wanted pattern
func ErrorContains(t *testing.T, out error, want string) {
	if out == nil {
		if want != "" {
			t.Errorf("got no error want %s", want)
		}
	}
	if !strings.Contains(out.Error(), want) {
		t.Errorf("want %s, got %v ", want, out)
	}
}
