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

try {
  //generate a hash with the productlist
  var sha512 = crypto.getSHA512();
  sha512.update(response.content);

  //convert to base64
  prodcache = {
      "etag": sha512.digest(),
      "productlist": response.content
  }

  // set headers
  context.setVariable("prodcache", JSON.stringify(prodcache));
  context.setVariable("response.header.etag", prodcache.etag);

} catch(e) {
  throw 'Error in set-product-cache javascript execution';
}