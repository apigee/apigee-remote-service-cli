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

package apigee

import (
	"fmt"
	"strconv"
	"strings"
)

// Revision represents a revision number. Edge returns rev numbers in string form.
// This marshals and unmarshals between that format and int.
type Revision int

// MarshalJSON implements the json.Marshaler interface. It marshals from
// a Revision holding an integer value like 2, into a string like "2".
// func (r *Revision) MarshalJSON() ([]byte, error) {
// 	rev := fmt.Sprintf("%d", r)
// 	return []byte(rev), nil
// }

// UnmarshalJSON implements the json.Unmarshaler interface. It unmarshals from
// a string like "2" (including the quotes), into an integer 2.
func (r *Revision) UnmarshalJSON(b []byte) error {
	rev, e := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(string(b), "\""), "\""), 10, 32)
	if e != nil {
		return e
	}

	*r = Revision(rev)
	return nil
}

func (r Revision) String() string {
	return fmt.Sprintf("%d", r)
}

// RevisionSlice is for sorting
type RevisionSlice []Revision

func (p RevisionSlice) Len() int           { return len(p) }
func (p RevisionSlice) Less(i, j int) bool { return p[i] < p[j] }
func (p RevisionSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
