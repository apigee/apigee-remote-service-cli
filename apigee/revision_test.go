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
	"sort"
	"testing"
)

func TestUnmarshalRevision(t *testing.T) {
	rev := Revision(0)
	want := `strconv.ParseInt: parsing "notgood": invalid syntax`

	if err := rev.UnmarshalJSON([]byte("notgood")); err == nil || err.Error() != want {
		t.Errorf("want %s, got %v", want, err)
	}

	if err := rev.UnmarshalJSON([]byte("1")); err != nil {
		t.Errorf("want no error got %v", err)
	}
	if rev.String() != "1" {
		t.Errorf("want 1 got %s", rev.String())
	}
}

func TestSortRevision(t *testing.T) {
	revs := []Revision{3, 2, 1}
	sort.Sort(RevisionSlice(revs))
	for i := 1; i <= 3; i += 1 {
		if int(revs[i-1]) != i {
			t.Errorf("want %d, got %d", i, revs[i-1])
		}
	}
}
