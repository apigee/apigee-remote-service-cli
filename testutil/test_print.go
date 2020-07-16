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
	"fmt"
	"strings"
	"testing"
)

// Printer is for capturing test output
func Printer(name string) *TestPrint {
	return &TestPrint{
		Name: name,
	}
}

// TestPrint is for capturing test output
type TestPrint struct {
	Name   string
	Prints []string
}

// Printf is for capturing test output
func (tp *TestPrint) Printf(format string, args ...interface{}) {
	val := fmt.Sprintf(format, args...)
	tp.Prints = append(tp.Prints, val)
}

// Check is for checking test output
func (tp *TestPrint) Check(t *testing.T, want []string) {
	if want == nil {
		want = []string{}
	}

	if len(want) != len(tp.Prints) {
		t.Errorf("%s want %d prints, got %d: %v", tp.Name, len(want), len(tp.Prints), tp.Prints)
	}

	for i, got := range tp.Prints {
		w := want[i]
		if w != got {
			t.Errorf("%s want[%d]:\n'%s', got: \n'%s'", tp.Name, i, w, got)
		}
	}

	tp.Prints = nil
}

// Check is for checking test output
func (tp *TestPrint) CheckPrefix(t *testing.T, want []string) {
	if want == nil {
		want = []string{}
	}

	if len(want) != len(tp.Prints) {
		t.Errorf("%s want %d prints, got %d: %v", tp.Name, len(want), len(tp.Prints), tp.Prints)
	}

	for i, got := range tp.Prints {
		w := want[i]
		if !strings.HasPrefix(got, w) {
			t.Errorf("%s want[%d] to start with:\n'%s', got: \n'%s'", tp.Name, i, w, got)
		}
	}

	tp.Prints = nil
}
