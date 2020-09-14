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
	"testing"
	"time"
)

func TestMarshalTimestamp(t *testing.T) {
	now := time.Now()
	ts := Timestamp{now}
	b, err := ts.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != ts.String() {
		t.Errorf("want %s, got %s", ts.String(), string(b))
	}
}

func TestEqualTimestamp(t *testing.T) {
	now := time.Now()
	ts1 := Timestamp{now}
	ts2 := Timestamp{now}

	if !ts1.Equal(ts2) {
		t.Errorf("%s should be equal to %s", ts1.String(), ts2.String())
	}
}

func TestUnmarshalTimestamp(t *testing.T) {
	ts := &Timestamp{}
	want := `strconv.ParseInt: parsing "notgood": invalid syntax`

	if err := ts.UnmarshalJSON([]byte("notgood")); err == nil || err.Error() != want {
		t.Errorf("want %s, got %v", want, err)
	}

	if err := ts.UnmarshalJSON([]byte("1599006721080")); err != nil {
		t.Errorf("want no error got %v", err)
	}
}
