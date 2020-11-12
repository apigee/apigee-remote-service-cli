// Code generated for package templates by go-bindata DO NOT EDIT. (@generated)
// sources:
// templates/istio-1.6/apigee-envoy-adapter.yaml
// templates/istio-1.6/envoyfilter-sidecar.yaml
// templates/istio-1.6/httpbin.yaml
// templates/istio-1.6/request-authentication.yaml
// templates/istio-1.7/apigee-envoy-adapter.yaml
// templates/istio-1.7/envoyfilter-sidecar.yaml
// templates/istio-1.7/httpbin.yaml
// templates/istio-1.7/request-authentication.yaml
// templates/native/envoy-config.yaml
package templates

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data, name string) ([]byte, error) {
	gz, err := gzip.NewReader(strings.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// Mode return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _istio16ApigeeEnvoyAdapterYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xbc\x56\xcd\x6e\xe3\x36\x10\xbe\xfb\x29\x88\xdc\x29\xdb\x6d\xf7\x10\x01\x7b\x08\xb6\x8b\x74\x81\x3a\x6b\x34\x69\xef\x13\x6a\x22\x11\xa5\x38\x2c\x39\xd2\x56\x15\xf4\xee\x85\x44\xd9\x96\x92\xa8\x76\x83\x60\x75\x91\x35\x3f\xdf\x7c\x9c\x1f\x73\xc0\xe9\x3f\xd0\x07\x4d\x36\x15\xe0\x5c\x58\xd7\xdb\xd5\x9f\xda\x66\xa9\xf8\x19\x9d\xa1\xa6\x44\xcb\xab\x12\x19\x32\x60\x48\x57\x42\x58\x28\xb1\x37\xd5\x39\xa2\xf4\x58\x12\xa3\x0c\xe8\x6b\xad\x50\xa2\xad\xa9\x19\x6d\x82\x03\x85\xa9\x68\xdb\xe4\xee\xf0\xd5\x75\xab\xe0\x50\xf5\x28\x1e\x9d\xd1\x0a\x42\x2a\xb6\x2b\x21\x02\x1a\x54\x4c\xbe\xd7\x08\x51\x02\xab\xe2\x57\x78\x44\x13\xa2\x40\xf4\xcc\xce\xc5\x64\x2c\x9d\x01\xc6\x11\x63\xc2\x78\x00\xb0\x96\x18\x58\x93\x3d\x62\x0a\x11\x74\x86\x0a\x7c\xa2\x03\x6b\x4a\x34\xad\x3d\x7e\xf3\x9a\xf1\xc6\xb9\x5f\x1e\x1e\xf6\x7b\x4f\x8f\xe8\x43\x2a\xae\xd8\x57\x78\x75\x74\x73\x9e\x4a\xe4\x02\xab\xd0\xfb\x38\xe0\x22\x15\xeb\x12\xd9\x6b\x15\x96\x8c\xc8\x73\x2a\xae\x3e\x6c\x36\xdb\x25\x9c\xa0\x0a\xec\x33\x5b\x30\xbb\x25\x98\xa0\x3c\x38\x3c\x43\x88\x9b\xde\xe4\x24\xeb\x53\x3e\x9a\x9a\x59\x52\x2f\x4a\x6b\x7c\xea\x43\x8b\xd4\xdb\x41\x76\x28\xe3\xf0\x1b\x55\xe5\x35\x37\x9f\xc8\x32\xfe\xcd\xa9\x10\x47\x37\x5f\xd9\x9b\xf0\x7b\x40\x9f\x8a\xeb\xeb\xeb\xb9\xf8\xd6\x53\xe5\x5e\x91\xdf\x91\xfd\x8d\x88\x53\xd1\x9f\x71\x54\x29\xb2\x0c\xda\xf6\xc5\x18\x25\xf2\xa2\x3e\x8c\x8f\x2e\x21\xef\x93\x96\x13\xe5\x06\xd7\xa3\xcb\x60\x23\x21\x03\xc7\xe8\xd3\xb6\x4d\xbe\xf4\x66\x0f\x90\x77\xdd\xd5\xdc\x75\x5f\x19\xb3\x27\xa3\x55\x93\x8a\x1b\xf3\x0d\x9a\x49\x79\xc8\xf3\x24\x9f\xf2\xc4\x74\x3f\x54\xfc\xc3\x66\xb3\x39\x6a\x8d\xae\xd1\x62\x08\x43\x5f\x9d\x9c\xc4\x50\xf2\x5b\xe4\xa9\x48\x88\xb1\xaf\x0a\x04\xc3\xc5\x3f\x73\xd5\x01\x7b\x3b\x11\x3f\x81\x36\x95\xc7\x87\xc2\x63\x28\xc8\x64\x71\xb2\x8e\x2e\xe8\x35\x65\xf7\xa8\xc8\x66\xfd\xd0\x9d\x58\x79\x84\x4c\x7f\x4f\x5a\x3f\x6e\x2e\xe2\x05\x3e\x0f\xd3\xd0\x52\x48\x69\x28\x97\x06\x6b\x34\x1f\x33\x7c\xac\xf2\x67\x5a\x45\xf6\x49\xe7\x1f\xd7\xf1\x3d\xbe\x92\x06\x4a\x33\x39\x6c\xa0\xca\x2b\x9c\x21\x1b\x5d\x6a\x0e\xf3\x63\x2a\x57\xf5\x6c\x36\xe5\x4c\x5a\x62\x49\xbe\x19\x14\x3b\x3d\xd1\x78\xfc\xab\xc2\xb0\x80\x71\x09\x44\x4d\xa6\x2a\x71\x47\x95\x9d\xb7\x53\xd9\x4b\xf6\x31\xe5\xf1\x3c\x13\xb0\xcb\x27\x20\x56\xf9\xab\x35\xcd\x38\x56\x6d\x2b\x85\x7e\x12\xc9\x97\x70\xfb\x69\xbf\x03\x0b\x39\x66\x5d\xb7\x12\xe2\xa0\xb8\xb1\x60\x1a\xd6\x2a\xdc\xa3\xf2\xc8\x83\xee\x35\x52\x70\xb0\x93\x61\x30\x7c\x49\x6f\xd9\xe0\x19\xa7\x18\x1c\x4d\xc0\x81\xc1\x67\xab\x28\xc3\xac\xbf\x3c\x16\xa3\x93\xe3\x71\x9c\xd7\x6c\xc2\x8b\xd8\x6c\x82\x8c\x99\x3d\x1b\xd5\x66\x8b\x41\xdc\x30\xfa\x4b\xe7\x5b\xd2\xbe\x92\xf0\x69\x90\x48\xeb\x4d\x7f\x67\xb1\x0f\x76\xe0\xd2\xff\xd5\x0b\x6f\x2e\xb9\x3c\x57\xc9\xf8\x39\x65\x93\xe1\x13\x54\x86\x77\x94\x61\x2a\x7e\xfa\x61\x3a\xf0\xd1\xf8\x6e\x40\x6c\xdb\xe4\xab\xcf\xbb\x4e\xb6\x6d\xf2\xd9\xd6\x5d\x27\x5f\x89\x71\xb6\x29\xe4\x72\xb5\xdf\xcc\x6c\x4c\x64\x95\x29\x88\xe4\x26\x61\x65\x6c\xb5\xe7\x15\x95\xff\xd9\x10\xef\x98\xa3\x79\x80\x13\x0d\x29\xe5\x6a\xba\xcd\x1d\x17\xb9\xfb\xd8\x07\xef\xb8\xc5\xcd\x37\x89\xb3\x5b\xc4\x61\x5b\x38\xde\x96\xf2\x74\x57\xc4\x73\x47\x3a\xb9\x77\xea\xc5\x36\x78\x0e\xfd\xdf\x00\x00\x00\xff\xff\x92\x92\x44\x7e\xc1\x0a\x00\x00"

func istio16ApigeeEnvoyAdapterYamlBytes() ([]byte, error) {
	return bindataRead(
		_istio16ApigeeEnvoyAdapterYaml,
		"istio-1.6/apigee-envoy-adapter.yaml",
	)
}

func istio16ApigeeEnvoyAdapterYaml() (*asset, error) {
	bytes, err := istio16ApigeeEnvoyAdapterYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-1.6/apigee-envoy-adapter.yaml", size: 2753, mode: os.FileMode(416), modTime: time.Unix(1605197952, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio16EnvoyfilterSidecarYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xdc\x56\x4d\x6f\xe3\x36\x10\xbd\xeb\x57\x0c\xe4\x6b\xad\x4d\x5a\xb4\x07\x9d\x9a\xcd\x3a\x5d\xa3\x59\x67\xe1\x78\xbb\xbd\x09\x34\x35\x96\xd8\x50\x24\x4b\x8e\x9c\x68\x83\xfc\xf7\x82\x22\x95\x58\xfe\x42\x8b\x1e\x0a\x34\x87\x58\xe0\x7c\xf0\xcd\x9b\x37\x23\x4d\x60\xae\x1c\x31\x29\x1d\x30\x05\x73\x47\x42\xc3\x4c\x6d\x75\x77\x23\x24\xa1\x05\xa1\x80\x6a\x84\x12\x37\xac\x95\x04\x8a\x35\xe8\x0c\xe3\x98\x25\x13\x98\x13\x30\x63\xa4\x40\x07\xa4\x81\x49\x09\x0e\xed\x56\x70\x74\x43\xd8\x9b\x3b\xcc\x37\xd0\xe9\x16\x1e\x85\xab\xbf\xf3\x4f\xc9\x04\x1a\xd6\x01\x31\x21\xb5\x85\x75\x07\xce\x20\x17\x9b\x4e\xa8\x0a\xd2\x47\x6d\x1f\xa4\x66\xe5\x3d\x4a\xe4\xa4\x6d\x0a\x1b\x6d\xa3\x87\xe0\x40\xcc\x56\x48\xce\x63\xf8\xe2\xd0\x41\xca\x8c\xa8\x10\xa7\x16\x1b\x4d\x38\x8d\x28\xa6\xe8\xeb\xc8\x82\x2d\xff\xf1\xe2\xe2\x22\x05\xe6\x62\x70\x96\x24\x13\x58\xd5\xc2\x81\x70\xf0\xa0\xf4\xa3\xf2\x35\xf8\x7b\x81\x6a\xab\xdb\xaa\x8e\x64\x5c\x66\x3f\x65\x49\xc2\x8c\xf8\x0d\xad\x13\x5a\xe5\xa0\x90\xbc\x9f\x50\x55\x26\xbc\x4b\x26\xf4\xbb\xed\x25\x93\xa6\x66\x3f\x24\x0f\x42\x95\xf9\x2e\x83\x49\x83\xc4\x4a\x46\x2c\x4f\xa0\xe7\x23\x87\x31\xda\xe7\xe7\x6c\xd5\x43\xba\x0f\xb0\xb3\x05\x6b\xf0\xe5\x25\x7a\xf7\xec\xe5\x03\xff\x89\xa7\xc0\x27\xda\x27\xc8\x9f\x01\x48\xb6\x46\xe9\xc2\x33\x40\xc3\x14\xab\xb0\x9c\xae\xbb\xe1\xca\x04\x80\x6b\xb5\x11\xd5\x67\x46\xbc\x46\x97\x27\x09\xc0\xb4\x6f\x62\xb7\xd2\x39\x7c\x5c\xad\x3e\x17\x37\xf3\xdb\xd5\x6c\x99\x84\x0c\xc4\xeb\x21\x1d\xd7\x8a\xf0\x89\x72\xb8\x9f\x7f\x98\x5d\x5f\x2d\x8b\xf9\xe2\xfd\xdd\x97\xc5\x87\x68\x96\xc2\x11\x2a\xb4\x83\x3b\xc0\xa6\xaf\xff\xba\x66\x42\xbd\x1d\x0e\xc7\xbb\x27\x03\x2f\xa1\x5f\x35\x91\x29\xb8\x56\x0a\x39\x09\xad\x8a\x50\x86\x1d\xf9\xbb\x76\x7d\x73\x24\xcd\x38\x91\xd5\x2d\xc5\xb8\xfe\x9f\xd9\xad\x46\x1b\xb4\x8c\xfa\x7e\xce\x17\xf7\xb3\xe5\xaa\x78\x3f\xbb\xb9\x5b\xce\xa2\x79\xcb\x64\x8b\x6f\xc9\x77\xd3\xe2\x13\x15\xac\xa5\xfa\xdb\xab\x35\x70\xba\x0b\xa5\xb2\x86\x17\x51\x86\x63\x88\x95\xd6\x95\xc4\xc2\x3b\xec\x63\x0f\xc2\x2c\x5a\x2b\xf6\x25\x72\x52\xd0\x7b\x19\x1c\x31\x2a\x8c\xc5\x8d\x78\x3a\x91\x62\x14\x40\xa2\x41\xdd\x52\x0e\x97\x6e\xe7\x7c\xd0\x6b\x11\x1b\x5e\xbc\xca\xd0\x8d\x11\x4f\x23\x21\xa1\xa1\xae\x6f\x5c\xf6\xc7\x63\x60\x47\xfd\xaf\xa5\x35\xd6\xc0\xdf\x51\xd7\xd5\xcd\x50\xf9\x59\x71\x8d\xb8\xb4\x6b\xc6\xcf\x88\xcc\xb6\x72\xbf\x25\x8c\x87\x4b\xaf\x6e\x6f\xef\xbe\x8e\x2c\x46\x4b\xc1\xc5\xbe\x3f\x0c\x2a\x89\xa4\xe8\x83\xaa\x01\x8c\x15\x8a\x0b\xc3\xe4\x41\x6c\xdf\x60\xd5\xe5\x40\xb6\xc5\xc3\x38\xb4\x8d\x70\x7e\x65\x1e\x0d\xac\x91\x95\x68\x73\x78\x86\xd4\x13\x90\xe6\x90\xfe\x3e\xbd\x0a\x68\xae\x5a\xaa\xb5\x15\xdf\xb0\x4c\xe1\x65\x4f\x48\x8b\xd9\xea\xeb\xdd\xf2\xd7\xff\x50\x4b\xe9\x59\x31\xa5\x67\xd5\xf0\x69\xb6\xfc\xe5\xc4\x8e\xa1\xce\x60\x59\x1c\xb6\x39\xfd\xd9\x5b\x3c\x3f\xfe\x37\x0b\x0b\x84\x19\xe1\x32\xae\x9b\x77\x01\x4b\x88\x8a\xea\xc9\xe2\x0b\xea\x14\xc2\x6c\xfb\x7d\xf6\x91\xc8\x5c\xbf\x5a\x3e\xed\x42\x1f\x94\xc4\xd1\xb9\x42\xea\x11\x96\xe9\xe1\x38\xf5\xab\xee\xcd\x7b\xc4\xd7\x61\x31\xe1\xb4\x69\xb4\x3a\x52\x69\xec\x90\xae\x8a\x63\xef\xc9\x63\x1b\x0c\xce\xee\xda\x68\x3f\xbd\x71\x23\xf1\xff\x7a\xef\x86\xbf\x7f\xb8\x7d\x01\x58\x59\x0a\x4f\x3f\x93\x85\xc5\x3f\x5b\x74\x54\x84\xa9\x70\x05\xe9\x7d\xea\x03\xfd\x39\x0b\xa3\x41\x1d\x4c\x5e\x3f\xca\x42\x01\x71\xa2\xf6\x42\x26\xc3\x40\x44\xb3\x3b\x48\xf9\x34\x8d\x58\x43\x13\x49\x3f\xa0\x3a\xe3\x64\xc4\x59\xa3\xb1\xba\x6c\x39\x9d\xbb\xc6\x7f\x32\xf2\x7e\x1e\x4e\x3b\x71\x29\x50\x91\x28\x4f\x7b\x94\xb8\x45\xe9\x27\x0b\x1b\x26\xe4\x5f\x01\x00\x00\xff\xff\x1b\x28\x64\x85\xc7\x0a\x00\x00"

func istio16EnvoyfilterSidecarYamlBytes() ([]byte, error) {
	return bindataRead(
		_istio16EnvoyfilterSidecarYaml,
		"istio-1.6/envoyfilter-sidecar.yaml",
	)
}

func istio16EnvoyfilterSidecarYaml() (*asset, error) {
	bytes, err := istio16EnvoyfilterSidecarYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-1.6/envoyfilter-sidecar.yaml", size: 2759, mode: os.FileMode(416), modTime: time.Unix(1605197952, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio16HttpbinYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x94\x91\x4f\x6b\xe3\x30\x10\xc5\xef\xfe\x14\x03\x7b\x76\xb2\xb9\x2d\xba\x2d\xec\x65\xa1\x14\x43\xa1\xf7\x89\xfc\xe2\x88\xe8\x1f\xd2\x24\x34\xfd\xf4\x45\x76\xe4\x38\x6e\x2e\x9d\x9b\x66\x1e\x3f\xbd\x37\xf3\x8b\xfe\x7a\x3a\x8a\xc4\xbd\xf1\x24\x9c\x06\x08\xe1\x83\x5d\xb4\xa0\x7f\x88\x36\x5c\x1d\xbc\x10\xfb\x9e\xde\x90\x2e\x46\x63\xd3\x70\x34\xef\x48\xd9\x04\xaf\xe8\xb2\x6b\x4e\xc6\xf7\xaa\x4e\x1b\x07\xe1\x9e\x85\x55\x43\xe4\xd9\x41\x55\xfa\xed\x9d\x23\x6b\x28\xea\x71\xe0\xb3\x95\x86\xc8\xf2\x1e\x36\x17\x39\x11\xc7\x78\xd7\xe7\x08\x5d\xda\x31\x24\x19\xe7\xed\x02\x38\xca\xcb\x44\xd1\x9f\xdf\xe3\x63\x32\xdf\xdd\x5b\x19\x16\x5a\x42\x7a\x82\x6e\xdb\xf6\x21\x05\xc7\x98\xb7\x73\x94\x7b\xee\x9f\xa6\xa9\x96\x13\xa2\x35\x9a\xb3\xa2\xdd\x37\x23\x8e\x45\x1f\x5f\x16\xa1\x57\xde\xa6\xd6\x65\xb1\x60\x22\x81\x8b\x96\x05\x37\xc2\xc2\x54\x29\xfb\x00\x7b\x8a\x5b\x03\xa7\x72\xec\x79\x40\xdf\xee\xaf\x65\x05\x66\x00\xc6\x51\x4d\x51\x4a\x07\x2f\x6c\x3c\xd2\xcc\x6f\xc9\x38\x1e\x4a\xe8\xa0\x4f\x48\x1b\x13\xb6\x27\x78\x0f\x39\x26\x18\xf9\xdc\xae\x3f\x1e\xd5\xdd\xd9\xda\x2e\x58\xa3\xaf\x8a\xfe\x1f\x5e\x83\x74\x09\xb9\x2c\xb8\xaa\xd6\xcb\x9d\x6a\x3e\x7d\xfd\x7a\xb6\x53\xef\xfc\x15\x00\x00\xff\xff\x35\x03\x1d\x9f\xc0\x02\x00\x00"

func istio16HttpbinYamlBytes() ([]byte, error) {
	return bindataRead(
		_istio16HttpbinYaml,
		"istio-1.6/httpbin.yaml",
	)
}

func istio16HttpbinYaml() (*asset, error) {
	bytes, err := istio16HttpbinYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-1.6/httpbin.yaml", size: 704, mode: os.FileMode(416), modTime: time.Unix(1605197952, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio16RequestAuthenticationYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x8c\x91\xbd\x6e\xdc\x3a\x10\x85\x7b\x3e\xc5\x81\xd9\x5d\x5c\x69\xe1\x56\x9d\x53\xc5\x4e\x10\x18\x86\x13\x17\x41\x0a\x8a\x1a\xaf\xc6\x4b\x91\x32\x67\xb8\x82\x62\xf8\xdd\x03\x69\xb3\x71\xb0\xd8\x00\x66\x35\x7f\x3c\x73\xf0\x8d\xc5\x97\xa4\xd4\xe0\x2a\xe2\xaa\x68\x9f\x32\xff\x74\xca\x29\xde\xa6\xc0\x7e\x86\xb8\x61\x0c\x04\x16\x48\x9f\xa6\x88\x96\x42\x9a\xe0\x62\x07\x9f\x86\x81\xa2\x52\x87\x54\xb4\x36\x16\x1f\x66\xc4\xa4\xe8\xdd\x9e\xe3\x16\xee\xac\xde\xff\x20\xd6\x9e\x32\xae\x6e\xaf\xf1\x89\x66\x41\xca\xb8\x79\xb8\x17\x78\xb7\x88\x1b\x8b\x22\xd4\xa1\x9d\xe1\x03\x53\x54\xa9\x71\xfd\x88\x39\x15\x50\x74\x6d\x20\x68\x4f\xe7\x85\x6f\x1e\xee\xa1\x69\x47\x51\x30\x71\x08\xc6\xa2\x25\x64\x7a\x2e\x9c\xa9\x5b\x1d\xff\xd9\xb9\xf4\x57\xaf\x53\xca\xbb\x65\x97\xf6\x34\x08\x85\x3d\x49\x6d\x8c\x1b\xf9\x1b\x65\xe1\x14\x1b\x08\xf9\x92\x59\xe7\x9a\x45\x39\xd5\x9c\x36\xfb\xcb\x96\xd4\x5d\x9a\x1d\xc7\xae\xc1\x1d\x3d\x17\x12\x5d\x0c\x51\x54\xf6\xab\x23\x33\x90\xba\xce\xa9\x6b\x0c\x10\xdd\x40\x0d\xdc\xc8\x5b\xa2\xdf\xa9\x8c\xce\x53\x83\x8e\x1e\x5d\x09\x6a\x64\x24\xbf\x4c\x0a\x05\xf2\x9a\xf2\x12\x03\x83\x53\xdf\x7f\x76\x2d\x05\x39\x14\x96\x52\x74\x5b\xea\xaa\x76\xfe\x4b\xf0\x69\xd2\xbb\x12\x68\x1d\xaa\xc0\x22\x85\x72\x83\x5e\x75\x94\x66\xb3\x79\x79\xa9\xef\x4a\x54\x1e\xe8\x63\x12\x7d\x7d\xdd\x64\x1a\x92\x52\x25\x94\xf7\xec\x69\xb3\x02\x5b\xe5\x9f\xa6\x9d\x7c\xcd\xfc\xfe\xaf\x9e\xb2\x8a\xb1\xa8\xaa\xca\x58\xbc\x0f\x9a\xc5\x01\xdb\x99\x03\x1a\x8b\x37\x6c\x16\x27\xe0\x8e\x85\x13\x74\x16\x07\x78\x4b\xfb\x0d\x9f\x3d\xc5\x67\xff\x85\x6f\x69\xe4\x03\xbd\x25\xac\xf0\x98\xd3\x70\x9c\xaf\x20\xa9\x64\x4f\xc7\x7c\x79\xf9\x70\xef\xdb\xcc\xd1\xf3\xe8\x82\x34\xf8\x7e\xf1\xdf\xc5\x8f\x5f\x01\x00\x00\xff\xff\x03\x51\x27\x2f\x46\x03\x00\x00"

func istio16RequestAuthenticationYamlBytes() ([]byte, error) {
	return bindataRead(
		_istio16RequestAuthenticationYaml,
		"istio-1.6/request-authentication.yaml",
	)
}

func istio16RequestAuthenticationYaml() (*asset, error) {
	bytes, err := istio16RequestAuthenticationYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-1.6/request-authentication.yaml", size: 838, mode: os.FileMode(416), modTime: time.Unix(1605197952, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio17ApigeeEnvoyAdapterYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xbc\x56\xcd\x6e\xe3\x36\x10\xbe\xfb\x29\x88\xdc\x29\xdb\x6d\xf7\x10\x01\x7b\x08\xb6\x8b\x74\x81\x3a\x6b\x34\x69\xef\x13\x6a\x22\x11\xa5\x38\x2c\x39\xd2\x56\x15\xf4\xee\x85\x44\xd9\x96\x92\xa8\x76\x83\x60\x75\x91\x35\x3f\xdf\x7c\x9c\x1f\x73\xc0\xe9\x3f\xd0\x07\x4d\x36\x15\xe0\x5c\x58\xd7\xdb\xd5\x9f\xda\x66\xa9\xf8\x19\x9d\xa1\xa6\x44\xcb\xab\x12\x19\x32\x60\x48\x57\x42\x58\x28\xb1\x37\xd5\x39\xa2\xf4\x58\x12\xa3\x0c\xe8\x6b\xad\x50\xa2\xad\xa9\x19\x6d\x82\x03\x85\xa9\x68\xdb\xe4\xee\xf0\xd5\x75\xab\xe0\x50\xf5\x28\x1e\x9d\xd1\x0a\x42\x2a\xb6\x2b\x21\x02\x1a\x54\x4c\xbe\xd7\x08\x51\x02\xab\xe2\x57\x78\x44\x13\xa2\x40\xf4\xcc\xce\xc5\x64\x2c\x9d\x01\xc6\x11\x63\xc2\x78\x00\xb0\x96\x18\x58\x93\x3d\x62\x0a\x11\x74\x86\x0a\x7c\xa2\x03\x6b\x4a\x34\xad\x3d\x7e\xf3\x9a\xf1\xc6\xb9\x5f\x1e\x1e\xf6\x7b\x4f\x8f\xe8\x43\x2a\xae\xd8\x57\x78\x75\x74\x73\x9e\x4a\xe4\x02\xab\xd0\xfb\x38\xe0\x22\x15\xeb\x12\xd9\x6b\x15\x96\x8c\xc8\x73\x2a\xae\x3e\x6c\x36\xdb\x25\x9c\xa0\x0a\xec\x33\x5b\x30\xbb\x25\x98\xa0\x3c\x38\x3c\x43\x88\x9b\xde\xe4\x24\xeb\x53\x3e\x9a\x9a\x59\x52\x2f\x4a\x6b\x7c\xea\x43\x8b\xd4\xdb\x41\x76\x28\xe3\xf0\x1b\x55\xe5\x35\x37\x9f\xc8\x32\xfe\xcd\xa9\x10\x47\x37\x5f\xd9\x9b\xf0\x7b\x40\x9f\x8a\xeb\xeb\xeb\xb9\xf8\xd6\x53\xe5\x5e\x91\xdf\x91\xfd\x8d\x88\x53\xd1\x9f\x71\x54\x29\xb2\x0c\xda\xf6\xc5\x18\x25\xf2\xa2\x3e\x8c\x8f\x2e\x21\xef\x93\x96\x13\xe5\x06\xd7\xa3\xcb\x60\x23\x21\x03\xc7\xe8\xd3\xb6\x4d\xbe\xf4\x66\x0f\x90\x77\xdd\xd5\xdc\x75\x5f\x19\xb3\x27\xa3\x55\x93\x8a\x1b\xf3\x0d\x9a\x49\x79\xc8\xf3\x24\x9f\xf2\xc4\x74\x3f\x54\xfc\xc3\x66\xb3\x39\x6a\x8d\xae\xd1\x62\x08\x43\x5f\x9d\x9c\xc4\x50\xf2\x5b\xe4\xa9\x48\x88\xb1\xaf\x0a\x04\xc3\xc5\x3f\x73\xd5\x01\x7b\x3b\x11\x3f\x81\x36\x95\xc7\x87\xc2\x63\x28\xc8\x64\x71\xb2\x8e\x2e\xe8\x35\x65\xf7\xa8\xc8\x66\xfd\xd0\x9d\x58\x79\x84\x4c\x7f\x4f\x5a\x3f\x6e\x2e\xe2\x05\x3e\x0f\xd3\xd0\x52\x48\x69\x28\x97\x06\x6b\x34\x1f\x33\x7c\xac\xf2\x67\x5a\x45\xf6\x49\xe7\x1f\xd7\xf1\x3d\xbe\x92\x06\x4a\x33\x39\x6c\xa0\xca\x2b\x9c\x21\x1b\x5d\x6a\x0e\xf3\x63\x2a\x57\xf5\x6c\x36\xe5\x4c\x5a\x62\x49\xbe\x19\x14\x3b\x3d\xd1\x78\xfc\xab\xc2\xb0\x80\x71\x09\x44\x4d\xa6\x2a\x71\x47\x95\x9d\xb7\x53\xd9\x4b\xf6\x31\xe5\xf1\x3c\x13\xb0\xcb\x27\x20\x56\xf9\xab\x35\xcd\x38\x56\x6d\x2b\x85\x7e\x12\xc9\x97\x70\xfb\x69\xbf\x03\x0b\x39\x66\x5d\xb7\x12\xe2\xa0\xb8\xb1\x60\x1a\xd6\x2a\xdc\xa3\xf2\xc8\x83\xee\x35\x52\x70\xb0\x93\x61\x30\x7c\x49\x6f\xd9\xe0\x19\xa7\x18\x1c\x4d\xc0\x81\xc1\x67\xab\x28\xc3\xac\xbf\x3c\x16\xa3\x93\xe3\x71\x9c\xd7\x6c\xc2\x8b\xd8\x6c\x82\x8c\x99\x3d\x1b\xd5\x66\x8b\x41\xdc\x30\xfa\x4b\xe7\x5b\xd2\xbe\x92\xf0\x69\x90\x48\xeb\x4d\x7f\x67\xb1\x0f\x76\xe0\xd2\xff\xd5\x0b\x6f\x2e\xb9\x3c\x57\xc9\xf8\x39\x65\x93\xe1\x13\x54\x86\x77\x94\x61\x2a\x7e\xfa\x61\x3a\xf0\xd1\xf8\x6e\x40\x6c\xdb\xe4\xab\xcf\xbb\x4e\xb6\x6d\xf2\xd9\xd6\x5d\x27\x5f\x89\x71\xb6\x29\xe4\x72\xb5\xdf\xcc\x6c\x4c\x64\x95\x29\x88\xe4\x26\x61\x65\x6c\xb5\xe7\x15\x95\xff\xd9\x10\xef\x98\xa3\x79\x80\x13\x0d\x29\xe5\x6a\xba\xcd\x1d\x17\xb9\xfb\xd8\x07\xef\xb8\xc5\xcd\x37\x89\xb3\x5b\xc4\x61\x5b\x38\xde\x96\xf2\x74\x57\xc4\x73\x47\x3a\xb9\x77\xea\xc5\x36\x78\x0e\xfd\xdf\x00\x00\x00\xff\xff\x92\x92\x44\x7e\xc1\x0a\x00\x00"

func istio17ApigeeEnvoyAdapterYamlBytes() ([]byte, error) {
	return bindataRead(
		_istio17ApigeeEnvoyAdapterYaml,
		"istio-1.7/apigee-envoy-adapter.yaml",
	)
}

func istio17ApigeeEnvoyAdapterYaml() (*asset, error) {
	bytes, err := istio17ApigeeEnvoyAdapterYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-1.7/apigee-envoy-adapter.yaml", size: 2753, mode: os.FileMode(416), modTime: time.Unix(1605197952, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio17EnvoyfilterSidecarYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xdc\x56\x41\x6f\xe3\x36\x13\xbd\xeb\x57\x0c\xec\xe3\xf7\x59\x9b\x74\x51\x14\xd0\xa9\x4e\xd6\xd9\x35\x9a\x4d\x16\x8e\xb7\xdb\x9b\xc2\x50\x63\x89\x0d\x45\xb2\xe4\xc8\xb1\x36\xc8\x7f\x2f\x28\x4a\x89\xa5\x58\xee\x2e\x8a\xa2\x40\x73\x08\x0c\xce\xcc\xe3\x9b\xc7\x37\xa4\xa6\xb0\x54\x8e\x98\x94\x0e\x98\x82\xa5\x23\xa1\x61\xa1\xb6\xba\xbe\x10\x92\xd0\x82\x50\x40\x05\x42\x86\x1b\x56\x49\x02\xc5\x4a\x74\x86\x71\x8c\xa3\x29\x2c\x09\x98\x31\x52\xa0\x03\xd2\xc0\xa4\x04\x87\x76\x2b\x38\xba\xae\xec\x25\x1d\x96\x1b\xa8\x75\x05\x0f\xc2\x15\xff\xf7\xbf\xa2\x29\x94\xac\x06\x62\x42\x6a\x0b\x77\x35\x38\x83\x5c\x6c\x6a\xa1\x72\xb8\x7d\xd0\xf6\x5e\x6a\x96\xdd\xa0\x44\x4e\xda\xde\xc2\x46\xdb\x36\x43\x70\x20\x66\x73\x24\xe7\x39\x7c\x76\xe8\xe0\x96\x19\x91\x23\xce\x2c\x96\x9a\x70\xd6\xb2\x98\xa1\xef\x23\x0e\xb1\xe4\xc7\x93\x93\x93\x5b\x60\xae\x2d\x8e\xa3\x68\x0a\xeb\x42\x38\x10\xae\x01\x0f\xad\x9f\xc6\x3f\xfd\x2f\x8e\x22\x66\xc4\xaf\x68\x9d\xd0\x2a\x01\x85\xe4\xe9\x08\x95\xc7\xc2\xe7\xc4\x42\xbf\xd9\x9e\x32\x69\x0a\xf6\x36\xba\x17\x2a\x4b\xf6\x05\x8b\x4a\x24\x96\x31\x62\x49\x04\x4d\xfb\x09\xf4\xc9\x3d\x3e\xc6\xeb\x86\xc1\x4d\x60\x19\x5f\xb1\x12\x9f\x9e\xda\xec\x46\xac\xa4\x93\x3b\xf2\x1d\x7b\xa0\xa1\x1e\x7e\x0d\x40\xb2\x3b\x94\x2e\xfc\x06\x28\x99\x62\x39\x66\xb3\xbb\xba\xdb\x32\x02\xe0\x5a\x6d\x44\xfe\x89\x11\x2f\xd0\x25\x51\x04\x30\x6b\xce\xac\x5e\xeb\x04\x3e\xac\xd7\x9f\xd2\x8b\xe5\xe5\x7a\xb1\x8a\x02\x02\xf1\xa2\x83\xe3\x5a\x11\xee\x28\x81\x9b\xe5\xbb\xc5\xf9\x7c\x95\x2e\xaf\xce\xae\x3f\x5f\xbd\x6b\xc3\x52\x38\x42\x85\xb6\x4b\x07\xd8\x34\xfd\x9f\x17\x4c\xa8\x97\xc5\x6e\x79\x7f\xa5\xd3\x25\x1c\x4f\x41\x64\x52\xae\x95\x42\x4e\x42\xab\x34\xb4\x61\x7b\xf9\xae\xba\xbb\x38\x00\xd3\x07\xb2\xba\xa2\xb6\xae\xf9\x67\xf6\xbb\xd1\x06\x2d\xa3\xe6\x3c\x97\x57\x37\x8b\xd5\x3a\x3d\x5b\x5c\x5c\xaf\x16\x6d\x78\xcb\x64\x85\x2f\xe0\xfb\xb0\x81\xbf\x6b\x78\xc6\xb8\xa3\x94\x55\x54\x7c\x7d\x4e\xa5\xda\x60\x96\x06\x99\xf7\xd9\x4d\x7e\xf6\x91\x49\xd2\x24\xc4\xb9\xd6\xb9\x44\x66\x84\x8b\xb9\x2e\xdf\x04\xe4\x50\xd4\x6e\x30\xc0\x8f\xb7\x3f\xc4\x8b\x1d\xcd\x7b\x7b\x01\xe4\xd6\xf0\xb4\xb5\x77\x5f\x8b\xb0\x43\xea\x13\x86\x22\x05\xc3\xa7\x95\x15\x43\x2f\x8e\x0e\xca\x00\xc1\x11\xa3\xd4\x58\xdc\x88\xdd\x08\x44\xaf\x80\x44\x89\xba\xa2\x04\x4e\xdd\xde\x7a\x37\x18\x69\xeb\xac\xf4\xd9\xef\xae\xcf\x78\x76\x48\xf9\xdf\x1f\x82\x32\xea\x3f\xed\xe1\x51\xb3\x7d\x8b\xa3\xe7\x17\x9d\x08\xdf\x6e\x68\x7b\xc7\xf8\x3f\xe4\x65\x0f\xed\x6d\xbc\x3a\x9b\x9f\xef\x81\xd9\x4a\x0e\x0f\x9c\xf1\xd0\xc7\xfc\xf2\xf2\xfa\x4b\x2f\x62\xb4\x14\x5c\x0c\xf3\xa1\xf3\x60\x2b\xb9\x7e\xa5\x29\x80\xb1\x42\x71\x61\x98\x7c\x55\xdb\xd8\x47\xd5\x09\x90\xad\xf0\x75\x1d\xda\x52\x38\x7f\xf3\x1f\x2c\x2c\x90\x65\x68\x13\x78\x84\x89\xd7\x74\x92\xc0\xe4\xb7\xd9\x3c\xb0\xf1\xc3\xaa\xad\xf8\x8a\xd9\x04\x9e\x06\x36\xbd\x5a\xac\xbf\x5c\xaf\x7e\xf9\x17\x9d\x3a\x39\x6a\xd5\xc9\x51\x83\x7d\x5c\xac\xde\x8f\x5c\x95\x7f\xe9\x99\xc9\xb8\x69\x70\x47\xa8\x1a\xa9\x9f\x4d\xd9\x3e\xb6\x63\x34\xe3\xed\xdb\xf8\x03\x91\x39\x7f\x8e\x7c\xdc\xe7\xdf\xd9\x89\xa3\x73\xa9\xd4\x3d\x42\xb3\xde\x10\xbc\xe4\xe4\xdd\x2c\x34\x77\x67\xff\x1e\x1b\xe9\x0d\xbe\x6b\x26\xc2\x56\x52\xe7\x7e\x18\x3c\xf9\xf7\xd6\xf0\x79\xb3\x78\xa9\xf3\xf3\x26\x69\x00\xce\x75\x59\x6a\x35\xb2\x33\x80\xd4\x79\x7a\xe8\xd3\xe2\xd0\x5d\x0c\x47\x5f\x8d\x36\x3e\xfe\x76\xb4\x42\xfc\xed\x17\x24\xfc\x7d\xe7\x3b\x02\xc0\xb2\x4c\xf8\x53\x66\x32\xb5\xf8\x47\x85\x8e\xd2\x30\x81\x2e\x25\x3d\x3c\xe1\x70\xca\x09\x0b\x63\x48\x35\x4c\x9f\x3f\x5b\x43\x03\xed\xf4\x0e\x4a\xa6\xdd\xf0\xb5\x61\xf7\x0a\x72\x37\x6b\xb9\x86\xa3\x24\x7d\x8f\xea\x48\x92\x11\x47\x83\xc6\xea\xac\xe2\x74\x6c\x1b\xff\x51\xcd\x9b\xd9\x1b\x4f\xe2\x52\xa0\x22\x91\x8d\x67\x64\xb8\x45\xe9\xa7\x18\x4b\x26\xe4\x9f\x01\x00\x00\xff\xff\xc6\x6f\x50\xc8\xe9\x0b\x00\x00"

func istio17EnvoyfilterSidecarYamlBytes() ([]byte, error) {
	return bindataRead(
		_istio17EnvoyfilterSidecarYaml,
		"istio-1.7/envoyfilter-sidecar.yaml",
	)
}

func istio17EnvoyfilterSidecarYaml() (*asset, error) {
	bytes, err := istio17EnvoyfilterSidecarYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-1.7/envoyfilter-sidecar.yaml", size: 3049, mode: os.FileMode(416), modTime: time.Unix(1605197952, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio17HttpbinYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x94\x91\x4f\x6b\xe3\x30\x10\xc5\xef\xfe\x14\x03\x7b\x76\xb2\xb9\x2d\xba\x2d\xec\x65\xa1\x14\x43\xa1\xf7\x89\xfc\xe2\x88\xe8\x1f\xd2\x24\x34\xfd\xf4\x45\x76\xe4\x38\x6e\x2e\x9d\x9b\x66\x1e\x3f\xbd\x37\xf3\x8b\xfe\x7a\x3a\x8a\xc4\xbd\xf1\x24\x9c\x06\x08\xe1\x83\x5d\xb4\xa0\x7f\x88\x36\x5c\x1d\xbc\x10\xfb\x9e\xde\x90\x2e\x46\x63\xd3\x70\x34\xef\x48\xd9\x04\xaf\xe8\xb2\x6b\x4e\xc6\xf7\xaa\x4e\x1b\x07\xe1\x9e\x85\x55\x43\xe4\xd9\x41\x55\xfa\xed\x9d\x23\x6b\x28\xea\x71\xe0\xb3\x95\x86\xc8\xf2\x1e\x36\x17\x39\x11\xc7\x78\xd7\xe7\x08\x5d\xda\x31\x24\x19\xe7\xed\x02\x38\xca\xcb\x44\xd1\x9f\xdf\xe3\x63\x32\xdf\xdd\x5b\x19\x16\x5a\x42\x7a\x82\x6e\xdb\xf6\x21\x05\xc7\x98\xb7\x73\x94\x7b\xee\x9f\xa6\xa9\x96\x13\xa2\x35\x9a\xb3\xa2\xdd\x37\x23\x8e\x45\x1f\x5f\x16\xa1\x57\xde\xa6\xd6\x65\xb1\x60\x22\x81\x8b\x96\x05\x37\xc2\xc2\x54\x29\xfb\x00\x7b\x8a\x5b\x03\xa7\x72\xec\x79\x40\xdf\xee\xaf\x65\x05\x66\x00\xc6\x51\x4d\x51\x4a\x07\x2f\x6c\x3c\xd2\xcc\x6f\xc9\x38\x1e\x4a\xe8\xa0\x4f\x48\x1b\x13\xb6\x27\x78\x0f\x39\x26\x18\xf9\xdc\xae\x3f\x1e\xd5\xdd\xd9\xda\x2e\x58\xa3\xaf\x8a\xfe\x1f\x5e\x83\x74\x09\xb9\x2c\xb8\xaa\xd6\xcb\x9d\x6a\x3e\x7d\xfd\x7a\xb6\x53\xef\xfc\x15\x00\x00\xff\xff\x35\x03\x1d\x9f\xc0\x02\x00\x00"

func istio17HttpbinYamlBytes() ([]byte, error) {
	return bindataRead(
		_istio17HttpbinYaml,
		"istio-1.7/httpbin.yaml",
	)
}

func istio17HttpbinYaml() (*asset, error) {
	bytes, err := istio17HttpbinYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-1.7/httpbin.yaml", size: 704, mode: os.FileMode(416), modTime: time.Unix(1605197952, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio17RequestAuthenticationYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x8c\x91\xbd\x6e\xdc\x3a\x10\x85\x7b\x3e\xc5\x81\xd9\x5d\x5c\x69\xe1\x56\x9d\x53\xc5\x4e\x10\x18\x86\x13\x17\x41\x0a\x8a\x1a\xaf\xc6\x4b\x91\x32\x67\xb8\x82\x62\xf8\xdd\x03\x69\xb3\x71\xb0\xd8\x00\x66\x35\x7f\x3c\x73\xf0\x8d\xc5\x97\xa4\xd4\xe0\x2a\xe2\xaa\x68\x9f\x32\xff\x74\xca\x29\xde\xa6\xc0\x7e\x86\xb8\x61\x0c\x04\x16\x48\x9f\xa6\x88\x96\x42\x9a\xe0\x62\x07\x9f\x86\x81\xa2\x52\x87\x54\xb4\x36\x16\x1f\x66\xc4\xa4\xe8\xdd\x9e\xe3\x16\xee\xac\xde\xff\x20\xd6\x9e\x32\xae\x6e\xaf\xf1\x89\x66\x41\xca\xb8\x79\xb8\x17\x78\xb7\x88\x1b\x8b\x22\xd4\xa1\x9d\xe1\x03\x53\x54\xa9\x71\xfd\x88\x39\x15\x50\x74\x6d\x20\x68\x4f\xe7\x85\x6f\x1e\xee\xa1\x69\x47\x51\x30\x71\x08\xc6\xa2\x25\x64\x7a\x2e\x9c\xa9\x5b\x1d\xff\xd9\xb9\xf4\x57\xaf\x53\xca\xbb\x65\x97\xf6\x34\x08\x85\x3d\x49\x6d\x8c\x1b\xf9\x1b\x65\xe1\x14\x1b\x08\xf9\x92\x59\xe7\x9a\x45\x39\xd5\x9c\x36\xfb\xcb\x96\xd4\x5d\x9a\x1d\xc7\xae\xc1\x1d\x3d\x17\x12\x5d\x0c\x51\x54\xf6\xab\x23\x33\x90\xba\xce\xa9\x6b\x0c\x10\xdd\x40\x0d\xdc\xc8\x5b\xa2\xdf\xa9\x8c\xce\x53\x83\x8e\x1e\x5d\x09\x6a\x64\x24\xbf\x4c\x0a\x05\xf2\x9a\xf2\x12\x03\x83\x53\xdf\x7f\x76\x2d\x05\x39\x14\x96\x52\x74\x5b\xea\xaa\x76\xfe\x4b\xf0\x69\xd2\xbb\x12\x68\x1d\xaa\xc0\x22\x85\x72\x83\x5e\x75\x94\x66\xb3\x79\x79\xa9\xef\x4a\x54\x1e\xe8\x63\x12\x7d\x7d\xdd\x64\x1a\x92\x52\x25\x94\xf7\xec\x69\xb3\x02\x5b\xe5\x9f\xa6\x9d\x7c\xcd\xfc\xfe\xaf\x9e\xb2\x8a\xb1\xa8\xaa\xca\x58\xbc\x0f\x9a\xc5\x01\xdb\x99\x03\x1a\x8b\x37\x6c\x16\x27\xe0\x8e\x85\x13\x74\x16\x07\x78\x4b\xfb\x0d\x9f\x3d\xc5\x67\xff\x85\x6f\x69\xe4\x03\xbd\x25\xac\xf0\x98\xd3\x70\x9c\xaf\x20\xa9\x64\x4f\xc7\x7c\x79\xf9\x70\xef\xdb\xcc\xd1\xf3\xe8\x82\x34\xf8\x7e\xf1\xdf\xc5\x8f\x5f\x01\x00\x00\xff\xff\x03\x51\x27\x2f\x46\x03\x00\x00"

func istio17RequestAuthenticationYamlBytes() ([]byte, error) {
	return bindataRead(
		_istio17RequestAuthenticationYaml,
		"istio-1.7/request-authentication.yaml",
	)
}

func istio17RequestAuthenticationYaml() (*asset, error) {
	bytes, err := istio17RequestAuthenticationYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "istio-1.7/request-authentication.yaml", size: 838, mode: os.FileMode(416), modTime: time.Unix(1605197952, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _nativeEnvoyConfigYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xe4\x58\x6f\x6f\xdb\x36\x13\x7f\x9f\x4f\x71\x70\xdf\x3c\xcf\x83\x5a\x71\x93\x16\x4f\x27\xa0\xc0\xdc\x74\xe8\x3f\x2f\x19\x92\x74\xdd\x5e\x11\x2c\x75\xb6\x99\x50\xa4\x46\x9e\x9c\xb8\x86\xbf\xfb\x40\x52\xb2\x25\x59\x4e\x52\xac\x45\x37\x4c\xef\xc4\x3b\xde\x91\x77\xbf\xfb\xf1\x48\x9e\xe5\x52\xa7\x07\x00\x5c\x08\x74\x8e\x29\x33\x63\x05\xa7\x79\x0a\x87\x94\x17\x87\xa8\x17\x66\xc9\x82\x52\xa2\xcc\xcc\xeb\x65\x99\x45\xe7\xfc\x14\x00\x67\xc4\x35\x12\x6b\x8d\x6d\x55\xe0\xc9\xd1\xff\x93\x51\x32\x4a\x9e\x54\x82\xc2\x58\x62\x0b\xae\x4a\x4c\xe1\x87\xd1\x68\x74\x00\x70\xe0\x88\x93\x14\xcc\xa2\x33\xa5\x15\x18\x8c\x28\xe9\x08\x35\xda\xf0\x33\x84\x8e\xf9\x8e\x53\x58\x6d\x1d\x8e\x82\xbb\xd1\xe3\x96\xa7\xe7\xa3\xe7\x23\x58\x7b\x5f\x7e\xf6\x54\x2a\x42\xcb\xc4\x9c\x4b\x5d\x99\x1c\x56\x83\x1b\x0f\x43\xd0\x3c\xc7\x14\xc2\xee\x93\x4a\x98\x68\xa4\x1b\x63\xaf\x93\x39\x51\xc1\x84\xd1\x1a\x05\x49\xa3\x59\xce\x35\x9f\xa1\xad\xe6\x02\xd0\xb2\xc0\xcc\x2b\x4c\xe5\x2c\xad\xbc\xc6\x6f\xf0\xa3\x97\x0d\xd2\xa0\x92\xcc\x8c\x99\x29\xe4\x85\x74\x89\x30\x79\x0c\x75\x82\xb7\x84\xda\x49\xa3\xdd\x43\xfd\x26\x8b\xe3\xe4\x0d\x51\x71\xb2\x91\xfc\xdc\x59\x10\x80\x0f\x32\x2b\x2c\x4e\xe5\x6d\x0a\x52\xcf\x7c\xb4\x98\xb7\xd7\xd0\xb1\xa6\x24\xac\x97\xdd\x18\x07\x58\x48\x4b\x25\x57\x6c\x6e\x1c\xb9\xb6\xa8\x8e\x54\x86\x53\x5e\x2a\x6a\xc9\x00\x32\x93\x87\x28\xc3\xe0\x7f\x83\x8e\x28\x78\xeb\x18\xf3\xe6\x72\x4e\x62\xee\x73\x5a\xaf\xf6\x30\xa4\xae\x67\x72\x77\xae\xff\x84\x2a\x1d\xa1\x4d\x61\xb5\x4a\x2e\xb9\x9d\x21\x5d\xa0\x5d\x48\x81\xc9\x29\xcf\x71\xbd\x6b\xa9\x31\x10\xc2\xdb\x00\x42\x43\xf4\x08\xd0\x63\x89\x13\xc2\xbb\x8f\x97\x40\xe6\x1a\xb5\x7b\x0c\x5c\x29\x73\xc3\x72\xe9\x9c\xd4\xb3\xf8\xe7\x60\xfc\xcb\x5b\x78\x8f\x4b\xe0\xca\x99\x83\xdd\x40\xb5\x21\xe5\x7d\x26\x57\x37\xc4\x78\x49\x73\xdd\x5a\x5d\x1b\x45\x9d\x85\x3f\x00\x48\x71\x66\xe5\xa9\xe3\x28\x59\x1c\x71\x55\xcc\x79\xf2\xee\x86\xc6\x25\xcd\x51\x93\x14\xdc\x43\xa7\xe3\xa7\xb0\x66\x21\xb3\x46\x65\x6c\x3f\x5e\xc8\x19\xf6\x26\x41\x3a\x57\xfa\x1c\x78\x9f\x2e\x3d\x3c\x5c\xad\x92\xf3\x52\x93\xcc\xf1\x8d\x71\xb4\x5e\x1f\x5a\xcc\x0d\xe1\xd0\xc5\xd4\x1c\x86\x70\xf6\xd8\xe1\x65\x26\x51\x8b\x5d\x94\xc4\x78\xb6\xad\x0c\x85\x92\xa8\xbb\x00\xf4\x5f\xd4\x63\x57\x37\xd7\xbd\x86\xaa\xc4\x97\x56\xf6\x4b\x01\xbc\xe8\xc1\x9b\x11\x68\xc9\xed\x31\xb4\x41\x67\x8c\xdd\xd0\xe7\xa2\x9e\xb8\x67\x8a\x77\x64\x4a\x4a\xe1\x59\xbf\x51\xc1\xc5\x1c\x59\x56\xda\x90\xbd\x7d\x3b\x70\x28\x8c\xce\x5c\x0a\xc7\x81\x73\xbb\x5f\xc1\x97\xca\xf0\x8c\x49\xcd\x72\x24\x9e\x71\xe2\xf5\x1a\xbb\x55\x5b\xaa\xfd\x45\xdb\x67\xb9\x2e\xe2\xdd\x12\xc6\x3f\x4a\x69\xfb\x73\x5b\xcb\x18\xd7\xcb\xfe\x2d\x55\x1a\x39\xea\x2e\x21\x6d\x17\x55\x63\x97\xc5\xc2\xeb\xdd\x4f\xad\xdb\xaa\xe4\x14\x56\xeb\xbd\xf5\x3f\x0e\x66\x62\x20\x1e\x56\xde\x78\x1b\xab\xee\xf3\xfe\xf2\xfe\x2a\xd5\xbd\xf1\x93\x2c\x8e\x92\x9f\x6e\x43\x61\x7f\xee\x58\x9e\xd9\x42\xb0\x0a\x71\xbb\x71\x8b\x87\xbd\xd7\xb9\x83\x5b\x5b\xe1\x1c\x76\x8a\x30\x58\xd8\x99\xbb\x01\xf1\x13\xd7\x15\x75\x74\x6b\xf8\xf9\xc0\x90\xdf\x90\x77\xe6\x0a\xde\x43\x02\xc3\xfb\xa8\xb4\x3f\x7f\xe7\x2f\xc7\x27\xf0\x1f\x8d\xbe\xd9\xe1\x76\x09\x53\x63\xeb\x9c\xd6\x5c\x6b\xf1\x0a\x05\xb1\x52\x7b\x4b\xc6\xca\xcf\x98\xc1\x8b\x17\x30\xe5\xca\xe1\x7f\x1f\x96\x73\xfb\x89\x8b\x6f\x9c\x6e\xef\xc2\x67\xda\x6f\xe8\x21\x55\xea\x3b\xbc\xc0\x11\x30\x9e\x4c\xce\x3e\xee\x48\x0b\xa3\xa4\x90\xfd\x05\x59\x25\xbb\xea\x3d\x8c\xed\x2f\xb9\xc2\x4a\x2d\x64\xc1\xd5\xde\x92\xf4\xf5\x0c\x64\xcb\xfe\x32\x2c\xd0\x86\x0a\x34\x7a\xaf\x81\x39\xf2\x2c\x1c\xef\x30\xf0\xb1\x1f\xa4\x30\xf8\x6d\x18\xd3\x37\x1c\x6f\xb2\x35\x80\x4e\xfd\xde\x95\x29\xdf\x4a\xd8\xaf\x99\xab\x9e\x0e\xae\xe1\xc9\x77\x6b\xe7\xb5\xcf\x86\xf1\x6d\xfb\x1d\x0e\xfb\x16\x78\x85\x51\x0a\x05\xd5\x38\xe5\x9a\xab\x25\x49\xb1\x9f\x7f\xb6\xc6\x66\xb5\xfb\x50\xd6\xdf\x00\x92\xd1\x95\x32\x33\x8f\x45\xdf\x86\xbe\xb6\x85\x18\x87\xc1\x89\x99\x9d\x04\xa5\x8e\x71\x61\xf2\xdc\xe8\x3d\x9e\xef\xe3\xa8\xfb\x58\xea\xaf\xf0\x94\xbf\xfb\x7c\xe9\x2c\x9e\x65\xd2\x97\x15\x57\xcc\x1f\x4a\xe8\x88\x45\x90\x3a\x46\x26\xa4\x73\x87\xb7\xd2\x8a\x57\x68\x09\x8f\xea\xc6\x19\x28\x74\xab\x15\xc0\x3b\x53\x3c\x02\x02\x1d\x56\xe2\x6e\x2b\x30\x84\xdb\x61\xdd\x52\x84\xc8\xf7\x75\x54\x4d\xa5\x42\xde\x29\x2c\xac\xc9\x4a\xb1\xd3\xc6\xb4\x94\x0a\xd5\xdf\x31\x36\x94\x62\x47\x26\xb3\xfd\x1a\x19\x2e\x50\x99\x02\x2d\xe6\x5c\xaa\x08\xfb\x2a\x7d\x15\x05\x1c\x40\x8c\x91\xd4\x58\x4b\x02\x65\xef\xf4\xf7\xb1\x1b\xab\xc2\x78\xb0\x2d\x88\xbb\x2e\x02\x15\x9f\xb1\xcd\xf9\x74\x14\xb7\xec\x41\x9f\xc2\xe4\xec\xf5\xdb\x93\xf1\x84\xbd\x3a\xbd\x08\xa3\x99\xf6\x15\x65\xae\xcb\x82\x4d\x79\x2e\xd5\x32\x85\x5f\x9f\xb2\xb3\xd3\xc9\xef\x41\xac\x3e\xb1\x40\xa1\xcb\x14\xce\xcf\x3e\x9c\xbe\x62\xe7\x67\x2f\xdf\x9e\x46\x91\x6f\xae\xb8\x73\x72\xa6\x7d\xc7\x52\x23\xa2\x0d\xd4\xbb\x6f\x2c\xa8\xb3\xc2\xc8\x46\xb7\x33\xf4\x0e\x77\x46\xe3\xb1\x18\x07\xdb\xc0\xeb\xdc\xa1\xeb\xaf\xff\x02\xbf\x3b\x0d\x06\x7b\x22\xde\xbd\xd7\xb5\x2f\xf9\x4f\x9f\x1e\xc7\x88\x5a\xae\x5d\x10\x44\x87\xb5\xa3\x26\x69\x75\x75\x5c\x42\xaa\x86\x60\x3f\x57\x7d\x19\x19\xf7\xda\xf7\x74\xfc\xa1\x70\x64\x91\xe7\x97\xca\x9d\xc4\x3a\xdb\x78\x70\x5a\xde\xbd\xf5\x7d\xf8\xac\xdb\xc4\x40\x20\xb0\xed\xf1\x6b\x58\xde\x47\x30\x11\x82\xf1\x6d\x24\x0c\x78\x0e\x3f\x62\x85\x35\x64\x84\x51\xcc\x14\x14\xce\xc9\xd8\xaa\x3e\x10\x62\xf7\xb3\xda\x77\x87\x59\xf7\xc5\xa8\x1f\x56\xcf\x46\xd5\x3d\xa6\x3a\x4a\xd4\xa7\x0e\x36\xe6\xc8\x15\xcd\x97\xac\xe0\x5a\x0a\x46\x73\x8b\x6e\x6e\x54\xb6\x75\xbc\x31\x94\x44\x43\x71\x02\x13\x73\x14\xd7\x8d\xcd\x37\x3a\xd7\xcd\x54\xa9\x09\xed\x82\xab\xd6\x9d\xac\x1e\x64\x57\x92\xc2\x15\xaf\x31\x41\x1b\x46\x96\x4f\xa7\x52\xb0\xde\xb9\xa5\xae\x97\xbb\x5d\x28\x6c\x03\xd0\x23\x3c\xde\x08\xc3\x61\xd9\x5c\xfc\x06\x11\x3b\xe4\x36\x4a\x8e\x2a\xa7\xab\x95\x9c\x42\x72\x39\xb9\x48\x5e\x49\xbb\x5e\x3f\x0a\x88\x15\xa5\x23\x93\xc3\xc5\xc5\x04\xb6\x6f\x4c\x40\xa6\x73\xcf\xee\x2f\x67\xf8\x87\xd4\x73\x85\x17\x52\xae\xbe\x61\x34\xb1\x18\x86\xd1\x92\x9c\xfa\xb3\x0d\x5d\xda\xee\x21\x1b\xa2\xf8\x7c\x18\x49\x7b\x72\x91\x9c\x58\xea\xbc\x2d\x15\x56\x2e\xbc\xde\x35\x2e\x37\x5a\xef\x71\xb9\x5e\xaf\x56\xa8\xb3\xf5\xfa\x7e\xea\x78\xf7\xf1\xfd\x05\xd4\xaf\x09\x1d\xda\xd8\x79\x38\xf8\x5b\x9d\x64\xfb\x5f\x37\xbe\x3b\xbd\x0c\xba\xcf\x37\xff\x92\xe3\xab\xbd\xe7\x3f\x03\x00\x00\xff\xff\xcb\x85\x1c\xaa\xf4\x17\x00\x00"

func nativeEnvoyConfigYamlBytes() ([]byte, error) {
	return bindataRead(
		_nativeEnvoyConfigYaml,
		"native/envoy-config.yaml",
	)
}

func nativeEnvoyConfigYaml() (*asset, error) {
	bytes, err := nativeEnvoyConfigYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "native/envoy-config.yaml", size: 6132, mode: os.FileMode(416), modTime: time.Unix(1605197952, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"istio-1.6/apigee-envoy-adapter.yaml":   istio16ApigeeEnvoyAdapterYaml,
	"istio-1.6/envoyfilter-sidecar.yaml":    istio16EnvoyfilterSidecarYaml,
	"istio-1.6/httpbin.yaml":                istio16HttpbinYaml,
	"istio-1.6/request-authentication.yaml": istio16RequestAuthenticationYaml,
	"istio-1.7/apigee-envoy-adapter.yaml":   istio17ApigeeEnvoyAdapterYaml,
	"istio-1.7/envoyfilter-sidecar.yaml":    istio17EnvoyfilterSidecarYaml,
	"istio-1.7/httpbin.yaml":                istio17HttpbinYaml,
	"istio-1.7/request-authentication.yaml": istio17RequestAuthenticationYaml,
	"native/envoy-config.yaml":              nativeEnvoyConfigYaml,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"istio-1.6": &bintree{nil, map[string]*bintree{
		"apigee-envoy-adapter.yaml":   &bintree{istio16ApigeeEnvoyAdapterYaml, map[string]*bintree{}},
		"envoyfilter-sidecar.yaml":    &bintree{istio16EnvoyfilterSidecarYaml, map[string]*bintree{}},
		"httpbin.yaml":                &bintree{istio16HttpbinYaml, map[string]*bintree{}},
		"request-authentication.yaml": &bintree{istio16RequestAuthenticationYaml, map[string]*bintree{}},
	}},
	"istio-1.7": &bintree{nil, map[string]*bintree{
		"apigee-envoy-adapter.yaml":   &bintree{istio17ApigeeEnvoyAdapterYaml, map[string]*bintree{}},
		"envoyfilter-sidecar.yaml":    &bintree{istio17EnvoyfilterSidecarYaml, map[string]*bintree{}},
		"httpbin.yaml":                &bintree{istio17HttpbinYaml, map[string]*bintree{}},
		"request-authentication.yaml": &bintree{istio17RequestAuthenticationYaml, map[string]*bintree{}},
	}},
	"native": &bintree{nil, map[string]*bintree{
		"envoy-config.yaml": &bintree{nativeEnvoyConfigYaml, map[string]*bintree{}},
	}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
