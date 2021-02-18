// Copyright 2018 Google LLC
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
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

func CopyFromEmbedded(embedded embed.FS, embeddedPath, extractDir string) error {

	// fs.WalkDirFunc
	copyOut := func(path string, source fs.DirEntry, err error) error {
		if err != nil {
			return errors.Wrap(err, "copyToTempDir")
		}
		if !source.IsDir() {
			bytes, err := embedded.ReadFile(path)
			if err != nil {
				return errors.Wrap(err, "ReadFile")
			}
			dest := filepath.Join(extractDir, path)
			if err = os.MkdirAll(filepath.Dir(dest), os.FileMode(0755)); err != nil {
				return errors.Wrap(err, "MkdirAll")
			}
			f, err := os.Create(dest)
			if err != nil {
				return errors.Wrap(err, "os.Create")
			}
			defer f.Close()
			_, err = f.Write(bytes)
			return errors.Wrap(err, "f.Write")
		}
		return nil
	}

	if err := fs.WalkDir(embedded, embeddedPath, copyOut); err != nil {
		return errors.Wrap(err, "fs.WalkDir")
	}

	return nil
}
