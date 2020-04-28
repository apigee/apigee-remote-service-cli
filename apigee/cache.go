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
	"net/url"
	"path"
)

const cachePath = "caches"

// CacheService is an interface for interfacing with the Apigee Edge Admin API
// dealing with caches.
type CacheService interface {
	Get(cachename string) (*Cache, *Response, error)
	Create(cache Cache) (*Response, error)
}

type Cache struct {
  Name string `json:"-,omitempty"`
  Description string `json:"description,omitempty"`
  ExpirySettings *expirySettings `json:"expirySettings,omitempty"`
  OverflowToDisk *bool `json:"overflowToDisk,omitempty"`
  SkipCacheIfElementSizeInKBExceeds *string `json:"skipCacheIfElementSizeInKBExceeds,omitempty"`
}

type expirySettings struct {
  ExpiryDate expiryDate `json:"expiryDate,omitempty"`
  ValuesNull string `json:"valuesNull,omitempty"`
}

type expiryDate struct {
  Value string `json:"value,omitempty"`
}

// CacheServiceOp represents a cache service operation
type CacheServiceOp struct {
	client *EdgeClient
}

var _ CacheService = &CacheServiceOp{}

// Get returns a response given a cache name
func (s *CacheServiceOp) Get(cachename string) (*Cache, *Response, error) {
	path := path.Join(cachePath, cachename)
	req, e := s.client.NewRequest("GET", path, nil)
	if e != nil {
		return nil, nil, e
	}
	returnedCache := Cache{}
	resp, e := s.client.Do(req, &returnedCache)
	if e != nil {
		return nil, resp, e
	}
	return &returnedCache, resp, e
}

// Create creates a cache and returns a response
func (s *CacheServiceOp) Create(cache Cache) (*Response, error) {
	path := path.Join(cachePath)
	u, _ := url.Parse(path)
	q := u.Query()
	q.Set("name", cache.Name)
	u.RawQuery = q.Encode()
	req, e := s.client.NewRequest("POST", u.String(), cache)
	if e != nil {
		return nil, e
	}
	resp, e := s.client.Do(req, &cache)
	return resp, e
}
