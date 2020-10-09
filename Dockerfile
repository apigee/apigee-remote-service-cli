# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This Dockerfile is for local build purpose.

ARG BUILD_CONTAINER=golang:1.15
ARG RUN_CONTAINER=ubuntu:xenial

FROM ${BUILD_CONTAINER} as builder

WORKDIR /app
ADD . .

RUN go mod download
RUN go build -a -o apigee-remote-service-cli .

#--- Build runtime container ---#
FROM ${RUN_CONTAINER}

# Copy app
COPY --from=builder /app/apigee-remote-service-cli .

# Run entrypoint
ENTRYPOINT ["/apigee-remote-service-cli"]
