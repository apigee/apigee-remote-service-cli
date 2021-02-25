// Copyright 2021 Google LLC
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

package cmd

import (
	"embed"
	"os"
	"path"
	"testing"
)

//go:embed "testdir"
var testdir embed.FS

func TestCopyFromEmbedded(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "extractdir")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(tmpdir)
	if err := CopyFromEmbedded(testdir, "testdir/testfile", tmpdir); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path.Join(tmpdir, "testdir/testfile"))
	if err != nil {
		t.Fatal(err)
	}

	if string(b) != "teststring" {
		t.Errorf("want 'teststring', got %s", string(b))
	}
}
