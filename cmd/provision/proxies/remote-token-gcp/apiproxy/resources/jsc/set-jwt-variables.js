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

var app = JSON.parse(context.getVariable('AccessEntity.Access-App-Info'));
// {"Credentials":{"Credential":[
//    {"Attributes":{},"ConsumerKey":"xxx","ConsumerSecret":"xx",
//      "ExpiresAt":"-1","IssuedAt":"1530046158362","ApiProducts":
//      {"ApiProduct": {"Name":"details product","Status":"approved"}},
//      "Scopes":{},"Status":"approved"}]}}

var apikey = context.getVariable('apikey');
var now = Date.now()
var credentials = app.credentials;

var apiProductsList = [];
try {
    if (app.status == "approved") {
        credentials.forEach(function(credential) {
            if (credential.consumerKey == apikey 
            && (credential.expiresAt == -1 || credential.expiresAt > now)
            && credential.status == "approved") {
                credential.apiProducts.forEach(function(apiProduct){
                    if (apiProduct.status == "approved") {
                      apiProductsList.push(apiProduct.apiproduct);
                    }
                });
            }
        });
    }
    
    if (apiProductsList.length > 0) {
        context.setVariable("isValidApiKey", "true");
    }
} catch (err) {
    print(err);
}

context.setVariable("appName", app.name);
context.setVariable("scope", context.getVariable("oauthv2accesstoken.AccessTokenRequest.scope"));
context.setVariable("apiProductList", apiProductsList.join());
context.setVariable("nbf", new Date(now).toUTCString());
context.setVariable("iss", context.getVariable("proxyProto") + "://" + context.getVariable("proxyHost") + context.getVariable("proxy.basepath") + context.getVariable("proxy.pathsuffix"));
context.setVariable("jti", 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0,
        v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
}));

// fetch the key and kid from the propertyset if secret does not exist
if (context.getVariable("private.secret.remote-service.key") === null) {
    context.setVariable("private.remote-service.key", context.getVariable("propertyset.remote-service.key"));
    context.setVariable("private.remote-service.properties.kid", context.getVariable("propertyset.remote-service.kid"));
} else {
    context.setVariable("private.remote-service.key", context.getVariable("private.secret.remote-service.key"));
    context.setVariable("private.remote-service.properties.kid", context.getVariable("private.secret.remote-service.properties.kid"));
}