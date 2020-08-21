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

var _istio16ApigeeEnvoyAdapterYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xbc\x56\x4b\x6f\xe3\x36\x10\xbe\xfb\x57\x10\xb9\xd3\x8f\xb6\x7b\x88\x80\x3d\x2c\xda\x62\xbb\x40\x93\x35\xba\x69\xef\x0c\x35\x96\x88\x92\x1c\x76\x38\x52\xab\x0a\xfa\xef\x05\x45\xd9\x96\x36\x4e\xe2\x06\x45\x79\xb0\xac\x79\x7c\xf3\xfa\x48\x4a\x05\xf3\x1b\x50\x34\xe8\x0b\xa1\x42\x88\x9b\x76\xb7\xfa\xdd\xf8\xb2\x10\x3f\x40\xb0\xd8\x39\xf0\xbc\x72\xc0\xaa\x54\xac\x8a\x95\x10\x5e\x39\x48\xa6\xa6\x02\x90\x04\x0e\x19\x64\x04\x6a\x8d\x06\x09\xbe\xc5\x6e\xb2\x89\x41\x69\x28\x44\xdf\xaf\xef\x8f\x6f\xc3\xb0\x12\x42\x79\x8f\xac\xd8\xa0\x8f\x09\x4e\x88\x68\x4a\xd0\x8a\xd6\x26\xb2\xc1\xb5\xc1\x0d\xc1\x9f\x64\x18\x3e\x84\xf0\xd3\xc3\xc3\x7e\x4f\xf8\x08\x14\x0b\x71\xc3\xd4\xc0\xcd\xe8\x12\x08\x1d\x70\x0d\x4d\x4c\xf6\x41\x71\x5d\x88\x8d\x03\x26\xa3\xe3\x25\x03\x24\x2e\xc4\xcd\xbb\xed\x76\x77\xc9\x3f\xea\x1a\x52\x4d\x35\x73\xb8\xe4\x1e\x35\xa9\x00\x2f\x24\xc0\x5d\x52\x9f\x65\x31\x80\x5e\xa5\x9f\x54\x20\x41\xb0\x46\xab\x58\x88\xdd\x4a\x88\x08\x16\x34\x23\xe5\xd2\x9d\x62\x5d\xff\xac\x1e\xc1\x4e\xbd\x10\x69\x06\xaf\x75\x97\xc1\x05\xab\x18\x26\x8c\xd9\x6c\xd2\xb2\x0b\xb8\xab\x00\xf3\x6a\x8f\x34\x68\x77\x79\x2e\x53\x01\xe3\x7f\xd0\x0d\x19\xee\xbe\x47\xcf\xf0\x17\x17\x42\x9c\xdc\xa8\xf1\x1f\xe2\xaf\x11\xa8\x10\xb7\xb7\xb7\x4b\xf1\x47\xc2\x26\x5c\x90\xdf\xa3\xff\x05\x91\x0b\x91\x3a\x3a\xa9\x34\x7a\x56\xc6\xa7\x51\x4f\x12\x79\x15\xd7\xf2\x32\x4e\x55\x69\x44\x15\x62\x65\x61\x33\xb9\x8c\x36\x52\x95\x2a\x30\x50\xd1\xf7\xeb\x4f\xc9\xec\x41\x55\xc3\x70\xb3\x74\xdd\x37\xd6\xee\xd1\x1a\xdd\x15\xe2\xd3\xe1\x1e\x79\x4f\x10\x13\xf5\x8f\x56\x89\x43\xb3\xae\xca\x73\xbe\xfb\x91\x5d\xef\xb6\xdb\xed\x49\x6b\x4d\x0b\x1e\x62\x1c\xb9\x7b\x76\x12\x23\xc5\x3e\x02\xcf\x45\x42\x4c\xfc\xad\x41\x59\xae\xff\x5e\xaa\x8e\xd8\xbb\x99\xf8\xa0\x8c\x6d\x08\x1e\x6a\x82\x58\xa3\x2d\x33\xb3\x4e\x2e\x40\x06\xcb\x2f\xa0\xd1\x97\x89\x74\xe7\xac\x08\x54\x69\xfe\xcf\xb4\xbe\xdd\x5e\x95\x97\xa2\x2a\xce\x43\x4b\x21\xa5\xc5\x4a\x5a\x68\xc1\xbe\x2f\xe1\xb1\xa9\xbe\xd2\x6a\xf4\x07\x53\xbd\xdf\xe4\xe7\xf4\x58\x77\xca\xd9\x59\xb1\x11\x1b\xd2\xb0\x40\xb6\xc6\x19\x8e\xcb\x32\x75\x68\x52\x36\x5b\xb7\x90\x3a\x70\x48\xdd\xa8\xb8\x33\x33\x0d\xc1\x1f\x0d\xc4\x67\x30\xae\x81\x68\xd1\x36\x0e\xee\xb0\xf1\x4b\x3a\xb9\x24\xd9\xe7\x96\xe7\x7a\x66\x60\xd7\xef\x83\x3c\xe5\xcf\xde\x76\x8b\xcd\xf5\x75\x04\x0c\x3c\xed\x91\x0d\xdb\xf8\x24\x12\xdb\x28\x73\xa2\xff\x16\x38\x8c\x7b\x48\x46\xd0\x04\xfc\x04\xf7\x39\xed\x45\xe8\x9c\xc0\x9b\x4e\x83\xdc\xc0\x3b\x15\x8a\x37\x34\x51\x3e\xdf\x84\x9c\xf8\x1c\xb4\x84\x83\x6a\x2c\xdf\x61\x09\x85\xf8\xee\x9b\x39\xe1\xb3\xf1\xfd\x3c\x6a\x53\x6a\x25\xfb\x7e\xfd\xa3\xd7\x58\x42\x99\x74\xc3\x20\xcf\x13\x90\x2f\xf6\xe9\xcd\xd1\xfb\x7e\xfd\x99\xaa\x61\xc8\xa1\xdb\x61\x90\xcb\x00\x52\xca\xd5\xfc\x3b\xe0\xf4\x09\xf0\x25\xb7\xe7\x3f\xbd\xff\xe7\xf7\xd3\xab\x77\xd3\xf1\x0e\x3a\x9d\xbe\xf2\x7c\xf6\xe4\x6a\x73\x3a\x15\x05\xfd\xe4\x76\x7d\x0d\xfd\x9f\x00\x00\x00\xff\xff\x81\x2e\x6c\x48\xfb\x08\x00\x00"

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

	info := bindataFileInfo{name: "istio-1.6/apigee-envoy-adapter.yaml", size: 2299, mode: os.FileMode(416), modTime: time.Unix(1598032701, 0)}
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

	info := bindataFileInfo{name: "istio-1.6/envoyfilter-sidecar.yaml", size: 2759, mode: os.FileMode(416), modTime: time.Unix(1598032701, 0)}
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

	info := bindataFileInfo{name: "istio-1.6/httpbin.yaml", size: 704, mode: os.FileMode(416), modTime: time.Unix(1598032701, 0)}
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

	info := bindataFileInfo{name: "istio-1.6/request-authentication.yaml", size: 838, mode: os.FileMode(416), modTime: time.Unix(1598032701, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio17ApigeeEnvoyAdapterYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xbc\x56\x4b\x6f\xe3\x36\x10\xbe\xfb\x57\x10\xb9\xd3\x8f\xb6\x7b\x88\x80\x3d\x2c\xda\x62\xbb\x40\x93\x35\xba\x69\xef\x0c\x35\x96\x88\x92\x1c\x76\x38\x52\xab\x0a\xfa\xef\x05\x45\xd9\x96\x36\x4e\xe2\x06\x45\x79\xb0\xac\x79\x7c\xf3\xfa\x48\x4a\x05\xf3\x1b\x50\x34\xe8\x0b\xa1\x42\x88\x9b\x76\xb7\xfa\xdd\xf8\xb2\x10\x3f\x40\xb0\xd8\x39\xf0\xbc\x72\xc0\xaa\x54\xac\x8a\x95\x10\x5e\x39\x48\xa6\xa6\x02\x90\x04\x0e\x19\x64\x04\x6a\x8d\x06\x09\xbe\xc5\x6e\xb2\x89\x41\x69\x28\x44\xdf\xaf\xef\x8f\x6f\xc3\xb0\x12\x42\x79\x8f\xac\xd8\xa0\x8f\x09\x4e\x88\x68\x4a\xd0\x8a\xd6\x26\xb2\xc1\xb5\xc1\x0d\xc1\x9f\x64\x18\x3e\x84\xf0\xd3\xc3\xc3\x7e\x4f\xf8\x08\x14\x0b\x71\xc3\xd4\xc0\xcd\xe8\x12\x08\x1d\x70\x0d\x4d\x4c\xf6\x41\x71\x5d\x88\x8d\x03\x26\xa3\xe3\x25\x03\x24\x2e\xc4\xcd\xbb\xed\x76\x77\xc9\x3f\xea\x1a\x52\x4d\x35\x73\xb8\xe4\x1e\x35\xa9\x00\x2f\x24\xc0\x5d\x52\x9f\x65\x31\x80\x5e\xa5\x9f\x54\x20\x41\xb0\x46\xab\x58\x88\xdd\x4a\x88\x08\x16\x34\x23\xe5\xd2\x9d\x62\x5d\xff\xac\x1e\xc1\x4e\xbd\x10\x69\x06\xaf\x75\x97\xc1\x05\xab\x18\x26\x8c\xd9\x6c\xd2\xb2\x0b\xb8\xab\x00\xf3\x6a\x8f\x34\x68\x77\x79\x2e\x53\x01\xe3\x7f\xd0\x0d\x19\xee\xbe\x47\xcf\xf0\x17\x17\x42\x9c\xdc\xa8\xf1\x1f\xe2\xaf\x11\xa8\x10\xb7\xb7\xb7\x4b\xf1\x47\xc2\x26\x5c\x90\xdf\xa3\xff\x05\x91\x0b\x91\x3a\x3a\xa9\x34\x7a\x56\xc6\xa7\x51\x4f\x12\x79\x15\xd7\xf2\x32\x4e\x55\x69\x44\x15\x62\x65\x61\x33\xb9\x8c\x36\x52\x95\x2a\x30\x50\xd1\xf7\xeb\x4f\xc9\xec\x41\x55\xc3\x70\xb3\x74\xdd\x37\xd6\xee\xd1\x1a\xdd\x15\xe2\xd3\xe1\x1e\x79\x4f\x10\x13\xf5\x8f\x56\x89\x43\xb3\xae\xca\x73\xbe\xfb\x91\x5d\xef\xb6\xdb\xed\x49\x6b\x4d\x0b\x1e\x62\x1c\xb9\x7b\x76\x12\x23\xc5\x3e\x02\xcf\x45\x42\x4c\xfc\xad\x41\x59\xae\xff\x5e\xaa\x8e\xd8\xbb\x99\xf8\xa0\x8c\x6d\x08\x1e\x6a\x82\x58\xa3\x2d\x33\xb3\x4e\x2e\x40\x06\xcb\x2f\xa0\xd1\x97\x89\x74\xe7\xac\x08\x54\x69\xfe\xcf\xb4\xbe\xdd\x5e\x95\x97\xa2\x2a\xce\x43\x4b\x21\xa5\xc5\x4a\x5a\x68\xc1\xbe\x2f\xe1\xb1\xa9\xbe\xd2\x6a\xf4\x07\x53\xbd\xdf\xe4\xe7\xf4\x58\x77\xca\xd9\x59\xb1\x11\x1b\xd2\xb0\x40\xb6\xc6\x19\x8e\xcb\x32\x75\x68\x52\x36\x5b\xb7\x90\x3a\x70\x48\xdd\xa8\xb8\x33\x33\x0d\xc1\x1f\x0d\xc4\x67\x30\xae\x81\x68\xd1\x36\x0e\xee\xb0\xf1\x4b\x3a\xb9\x24\xd9\xe7\x96\xe7\x7a\x66\x60\xd7\xef\x83\x3c\xe5\xcf\xde\x76\x8b\xcd\xf5\x75\x04\x0c\x3c\xed\x91\x0d\xdb\xf8\x24\x12\xdb\x28\x73\xa2\xff\x16\x38\x8c\x7b\x48\x46\xd0\x04\xfc\x04\xf7\x39\xed\x45\xe8\x9c\xc0\x9b\x4e\x83\xdc\xc0\x3b\x15\x8a\x37\x34\x51\x3e\xdf\x84\x9c\xf8\x1c\xb4\x84\x83\x6a\x2c\xdf\x61\x09\x85\xf8\xee\x9b\x39\xe1\xb3\xf1\xfd\x3c\x6a\x53\x6a\x25\xfb\x7e\xfd\xa3\xd7\x58\x42\x99\x74\xc3\x20\xcf\x13\x90\x2f\xf6\xe9\xcd\xd1\xfb\x7e\xfd\x99\xaa\x61\xc8\xa1\xdb\x61\x90\xcb\x00\x52\xca\xd5\xfc\x3b\xe0\xf4\x09\xf0\x25\xb7\xe7\x3f\xbd\xff\xe7\xf7\xd3\xab\x77\xd3\xf1\x0e\x3a\x9d\xbe\xf2\x7c\xf6\xe4\x6a\x73\x3a\x15\x05\xfd\xe4\x76\x7d\x0d\xfd\x9f\x00\x00\x00\xff\xff\x81\x2e\x6c\x48\xfb\x08\x00\x00"

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

	info := bindataFileInfo{name: "istio-1.7/apigee-envoy-adapter.yaml", size: 2299, mode: os.FileMode(416), modTime: time.Unix(1598032701, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio17EnvoyfilterSidecarYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xdc\x56\x41\x6f\xe3\x36\x13\xbd\xeb\x57\x0c\xec\xe3\xf7\x59\x9b\x74\x51\x14\xd0\xa9\x4e\xd6\xd9\x35\x9a\x4d\x16\x8e\xb7\xdb\x9b\xc2\x50\x63\x89\x0d\x45\xb2\xe4\xc8\xb1\x36\xc8\x7f\x2f\x28\x4a\x89\xa5\x58\xee\x2e\x8a\xa2\x40\x73\x08\x0c\xce\xcc\xe3\x9b\xc7\x37\xa4\xa6\xb0\x54\x8e\x98\x94\x0e\x98\x82\xa5\x23\xa1\x61\xa1\xb6\xba\xbe\x10\x92\xd0\x82\x50\x40\x05\x42\x86\x1b\x56\x49\x02\xc5\x4a\x74\x86\x71\x8c\xa3\x29\x2c\x09\x98\x31\x52\xa0\x03\xd2\xc0\xa4\x04\x87\x76\x2b\x38\xba\xae\xec\x25\x1d\x96\x1b\xa8\x75\x05\x0f\xc2\x15\xff\xf7\xbf\xa2\x29\x94\xac\x06\x62\x42\x6a\x0b\x77\x35\x38\x83\x5c\x6c\x6a\xa1\x72\xb8\x7d\xd0\xf6\x5e\x6a\x96\xdd\xa0\x44\x4e\xda\xde\xc2\x46\xdb\x36\x43\x70\x20\x66\x73\x24\xe7\x39\x7c\x76\xe8\xe0\x96\x19\x91\x23\xce\x2c\x96\x9a\x70\xd6\xb2\x98\xa1\xef\x23\x0e\xb1\xe4\xc7\x93\x93\x93\x5b\x60\xae\x2d\x8e\xa3\x68\x0a\xeb\x42\x38\x10\xae\x01\x0f\xad\x9f\xc6\x3f\xfd\x2f\x8e\x22\x66\xc4\xaf\x68\x9d\xd0\x2a\x01\x85\xe4\xe9\x08\x95\xc7\xc2\xe7\xc4\x42\xbf\xd9\x9e\x32\x69\x0a\xf6\x36\xba\x17\x2a\x4b\xf6\x05\x8b\x4a\x24\x96\x31\x62\x49\x04\x4d\xfb\x09\xf4\xc9\x3d\x3e\xc6\xeb\x86\xc1\x4d\x60\x19\x5f\xb1\x12\x9f\x9e\xda\xec\x46\xac\xa4\x93\x3b\xf2\x1d\x7b\xa0\xa1\x1e\x7e\x0d\x40\xb2\x3b\x94\x2e\xfc\x06\x28\x99\x62\x39\x66\xb3\xbb\xba\xdb\x32\x02\xe0\x5a\x6d\x44\xfe\x89\x11\x2f\xd0\x25\x51\x04\x30\x6b\xce\xac\x5e\xeb\x04\x3e\xac\xd7\x9f\xd2\x8b\xe5\xe5\x7a\xb1\x8a\x02\x02\xf1\xa2\x83\xe3\x5a\x11\xee\x28\x81\x9b\xe5\xbb\xc5\xf9\x7c\x95\x2e\xaf\xce\xae\x3f\x5f\xbd\x6b\xc3\x52\x38\x42\x85\xb6\x4b\x07\xd8\x34\xfd\x9f\x17\x4c\xa8\x97\xc5\x6e\x79\x7f\xa5\xd3\x25\x1c\x4f\x41\x64\x52\xae\x95\x42\x4e\x42\xab\x34\xb4\x61\x7b\xf9\xae\xba\xbb\x38\x00\xd3\x07\xb2\xba\xa2\xb6\xae\xf9\x67\xf6\xbb\xd1\x06\x2d\xa3\xe6\x3c\x97\x57\x37\x8b\xd5\x3a\x3d\x5b\x5c\x5c\xaf\x16\x6d\x78\xcb\x64\x85\x2f\xe0\xfb\xb0\x81\xbf\x6b\x78\xc6\xb8\xa3\x94\x55\x54\x7c\x7d\x4e\xa5\xda\x60\x96\x06\x99\xf7\xd9\x4d\x7e\xf6\x91\x49\xd2\x24\xc4\xb9\xd6\xb9\x44\x66\x84\x8b\xb9\x2e\xdf\x04\xe4\x50\xd4\x6e\x30\xc0\x8f\xb7\x3f\xc4\x8b\x1d\xcd\x7b\x7b\x01\xe4\xd6\xf0\xb4\xb5\x77\x5f\x8b\xb0\x43\xea\x13\x86\x22\x05\xc3\xa7\x95\x15\x43\x2f\x8e\x0e\xca\x00\xc1\x11\xa3\xd4\x58\xdc\x88\xdd\x08\x44\xaf\x80\x44\x89\xba\xa2\x04\x4e\xdd\xde\x7a\x37\x18\x69\xeb\xac\xf4\xd9\xef\xae\xcf\x78\x76\x48\xf9\xdf\x1f\x82\x32\xea\x3f\xed\xe1\x7d\x7f\x7d\x8b\x89\xe7\x17\x5d\xdf\xdf\xee\x61\x7b\xc7\xf8\x3f\x64\x5f\x0f\xed\x9d\xbb\x3a\x9b\x9f\xef\x81\xd9\x4a\x0e\xcf\x98\xf1\xd0\xc7\xfc\xf2\xf2\xfa\x4b\x2f\x62\xb4\x14\x5c\x0c\xf3\xa1\xb3\x5d\xab\xb2\x7e\x25\x23\x80\xb1\x42\x71\x61\x98\x7c\x55\xdb\x38\x46\xd5\x09\x90\xad\xf0\x75\x1d\xda\x52\x38\x7f\xd9\x1f\x2c\x2c\x90\x65\x68\x13\x78\x84\x89\xd7\x74\x92\xc0\xe4\xb7\xd9\x3c\xb0\xf1\xf3\xa9\xad\xf8\x8a\xd9\x04\x9e\x06\xce\xbc\x5a\xac\xbf\x5c\xaf\x7e\xf9\x17\xcd\x39\x39\xea\xce\xc9\x51\x83\x7d\x5c\xac\xde\x8f\xdc\x8e\x7f\xe9\x99\xc9\xb8\x69\x70\x47\xa8\x1a\xa9\x9f\x4d\xd9\xbe\xaf\x63\x34\xe3\xed\xdb\xf8\x03\x91\x39\x7f\x8e\x7c\xdc\xe7\xdf\xd9\x89\xa3\x73\xa9\xd4\x3d\x42\xb3\xde\x10\xbc\xe4\xe4\xdd\x2c\x34\xd7\x65\xff\xea\x1a\xe9\x0d\xbe\x6b\x26\xc2\x56\x52\xe7\x7e\x18\x3c\xf9\xf7\xd6\xf0\x79\xb3\x78\xa9\xf3\xf3\x26\x69\x00\xce\x75\x59\x6a\x35\xb2\x33\x80\xd4\x79\x7a\xe8\x6b\xe2\xd0\xf5\x0b\x47\x1f\x8a\x36\x3e\xfe\x5c\xb4\x42\xfc\xed\x47\x23\xfc\x7d\xe7\xd3\x01\xc0\xb2\x4c\xf8\x53\x66\x32\xb5\xf8\x47\x85\x8e\xd2\x30\x81\x2e\x25\x3d\x3c\xe1\x70\xca\x09\x0b\x63\x48\x35\x4c\x9f\xbf\x54\x43\x03\xed\xf4\x0e\x4a\xa6\xdd\xf0\xb5\x61\xf7\x0a\x72\x37\x6b\xb9\x86\xa3\x24\x7d\x8f\xea\x48\x92\x11\x47\x83\xc6\xea\xac\xe2\x74\x6c\x1b\xff\x1d\xcd\x9b\xd9\x1b\x4f\xe2\x52\xa0\x22\x91\x8d\x67\x64\xb8\x45\xe9\xa7\x18\x4b\x26\xe4\x9f\x01\x00\x00\xff\xff\xc4\x4b\xcf\xf3\xdc\x0b\x00\x00"

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

	info := bindataFileInfo{name: "istio-1.7/envoyfilter-sidecar.yaml", size: 3036, mode: os.FileMode(416), modTime: time.Unix(1598032701, 0)}
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

	info := bindataFileInfo{name: "istio-1.7/httpbin.yaml", size: 704, mode: os.FileMode(416), modTime: time.Unix(1598032701, 0)}
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

	info := bindataFileInfo{name: "istio-1.7/request-authentication.yaml", size: 838, mode: os.FileMode(416), modTime: time.Unix(1598032701, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _nativeEnvoyConfigYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xe4\x58\x5f\x93\xdb\xb6\x11\x7f\xd7\xa7\xd8\x91\x5f\xda\x4e\xc4\x93\xcf\xce\x34\xe5\x4c\x66\xaa\x9c\xdb\xc4\xb6\x7a\x97\xb9\x73\xea\xf6\x09\x03\x83\x2b\x09\x77\x20\x80\x02\xa0\xee\x64\x8d\xbe\x7b\x07\x00\x29\x91\x14\xa8\x53\xda\x78\xd2\x4e\xf8\x46\xec\x62\x17\xd8\x3f\xbf\xdd\x05\x2d\x4a\x2e\xf3\x11\x00\x65\x0c\xad\x25\x42\x2d\x89\xa6\x6e\x95\xc3\x85\x2b\xf5\x05\xca\xb5\xda\x90\xc0\x94\x09\xb5\xf4\x7c\x45\x61\xd0\x5a\xbf\x05\xc0\x2a\xf6\x80\x8e\x74\xd6\x0e\x2c\xf0\xf2\xf2\x8f\xd9\x34\x9b\x66\x2f\x6b\x82\x56\xc6\x91\x35\x15\x15\xe6\xf0\xa7\xe9\x74\x3a\x02\x18\x01\x58\x47\x1d\x67\xc4\xa0\x55\x95\x61\x18\xc4\x08\x6e\x1d\x4a\x34\xe1\x67\x02\x3d\x05\x3d\xb5\xb0\x3d\xa8\x9c\x06\x85\xd3\xaf\x3a\xba\xbe\x99\x7e\x33\x85\x5d\xd4\x06\xb0\xe0\xc2\xa1\x21\x6c\x45\xb9\xac\x45\x4e\xea\xc5\xbd\x86\x09\x48\x5a\x62\x0e\xe1\xfe\x59\x4d\xcc\x24\xba\x47\x65\x1e\xb2\x95\x73\x9a\x30\x25\x25\x32\xc7\x95\x24\x25\x95\x74\x89\xa6\xde\x0b\xe0\x36\x1a\x0b\xcf\xb0\xe0\xcb\xbc\xd6\x1a\xbf\xf1\x9f\x3d\x6d\x9c\x07\x96\x6c\xa9\xd4\x52\x20\xd5\xdc\x66\x4c\x95\xd1\xd8\x19\x3e\x39\x94\x96\x2b\x69\xcf\xd5\x9b\xad\x5f\x65\x3f\x38\xa7\xaf\xf6\x94\xbf\xf5\x0e\x14\x8d\x4c\xb4\xc1\x05\x7f\xca\x81\xcb\xa5\xb7\x16\xf1\xf2\x5a\x3c\x46\x55\x0e\x9b\x63\xb7\xd6\x01\xd6\xdc\xb8\x8a\x0a\xb2\x52\xd6\xd9\x2e\xa9\xb1\x54\x81\x0b\x5a\x09\xd7\xa1\x01\x14\xaa\x0c\x56\x86\xf1\x1f\xc6\x3d\x52\xd0\xd6\x13\xe6\xc5\x95\xd4\xb1\x95\xf7\x69\x73\xda\x8b\xe0\xba\xc4\xe6\xfe\x5e\xff\x31\x51\x59\x87\x26\x87\xed\x36\xfb\x40\xcd\x12\xdd\x1d\x9a\x35\x67\x98\x5d\xd3\x12\x77\xc7\x92\xa2\xaf\x34\x1a\xd2\xc4\x45\xe2\xfe\xf1\xeb\x06\x83\x37\x5e\x56\x6c\x24\x2d\x39\x23\x0b\x65\x1e\xa9\x29\x88\x36\xea\x69\x93\xda\xfb\x9f\xba\x7e\x58\x8b\xf7\xfa\x8f\x68\x6e\xbd\x25\xae\xc2\x99\x93\x6a\xbd\xcb\x88\xc1\x47\xc3\x1d\x12\xc1\x1d\x1a\x2a\x12\xd6\xf9\x41\x59\xb7\xdb\x01\xbc\x80\x9a\xd7\x42\x4e\x2b\xb7\x52\x86\xbb\x0d\x2c\x94\x81\x99\xe6\x4b\x44\xd0\x46\x15\x15\x73\xc0\x56\xc8\x1e\x46\x9d\xe0\x0e\xe1\xd9\x4a\xa4\x51\xdb\xad\xa9\x7c\x1a\xbe\xdc\xe8\xd8\x45\x69\xbf\x9c\x61\xd5\xb8\xb1\x56\x7a\xd2\xa0\x97\x54\xe8\x15\xcd\xfe\x1a\x38\x93\x36\x2d\xa4\x25\x8c\xb2\x55\x3a\x4d\xfc\x57\x67\x43\x4a\x41\x67\xe7\xd1\x46\x2f\x5a\x28\xf5\x50\x69\xb2\xa0\x25\x17\x9b\x1c\xfe\xfe\x9a\xdc\x5c\xcf\xff\xd9\x35\xe5\x0b\x40\x0f\x6b\xd4\x21\xbc\xfb\xf8\x01\x9c\x7a\x40\x69\xbf\x02\x2a\x84\x7a\x24\x25\xb7\x96\xcb\x65\xfc\xb3\x30\xfb\xf1\x2d\xbc\xc7\x0d\x50\x61\xd5\x79\xde\xb8\x7f\x74\xc4\xfb\x5d\x0e\x7b\x00\x7e\x11\x17\xec\x15\xed\xcd\xfe\xee\xd1\xcd\x2a\xb7\x42\xe9\x38\xa3\x1e\xc5\x7a\x7a\xb4\x51\x6b\x5e\xb4\x40\xfa\xf0\xd1\x10\x9b\xa9\xbc\xe3\xd6\x56\x1e\x0e\xbc\x4e\x9b\x5f\x5c\x6c\xb7\xd9\x6d\x25\x1d\x2f\x31\x46\xfc\x85\xc1\x52\x39\x9c\xd8\x98\x07\x17\xc1\x9c\x09\x39\xb4\x2a\x38\x4a\x76\x0c\x58\xd1\x9e\x5d\x29\x13\x26\x38\xca\x3e\x16\xfa\x2f\xf2\x91\xfb\xc7\x87\xa4\xa0\x3a\x87\x2a\xc3\xd3\x54\x00\x4f\x3a\xfb\x32\x0c\x8d\xb3\x03\x82\xf6\x40\x19\x6d\x37\xf1\xbe\x68\x36\x0e\x6c\xf1\x8a\x54\xe5\x72\xf8\x3a\x2d\x34\x86\x77\x51\x99\xe0\xbd\xa1\x1b\x58\x64\x4a\x16\x36\x87\x57\xa1\x01\xe8\x7f\x9a\x6e\x84\xa2\x05\xe1\x92\x94\xe8\x68\x41\x1d\x6d\xce\xd8\x2f\x20\x95\x18\xae\x1f\x29\xc9\x4d\x3d\x39\xae\x26\xf8\xaf\x8a\x9b\xb4\x6f\x1b\x1a\xa1\x72\x00\xd8\x6b\x8e\x12\x65\xbf\x36\x1e\x0e\xd5\xc4\x2e\x89\x89\x97\xbc\x4f\xc3\xdb\xc9\xe4\x1c\xb6\xbb\xc1\xfc\xaf\x21\x39\x18\xe2\xbc\xf4\xc6\xa7\x98\x75\x9f\xbf\x30\xc0\xee\xf5\x64\xeb\xcb\xec\x2f\x4f\x21\xb1\x3f\xf7\x24\x2f\x8d\x66\xa4\x8e\xb8\x63\xbb\xc5\xce\xd3\xf3\x9c\x28\xf3\x1d\x73\x4e\x7a\x49\x18\x24\x1c\xd7\xfb\x26\x88\x5f\xda\x3e\xa9\xc7\xdb\x84\x9f\x37\x8c\xf3\x17\xf2\xca\xac\xa6\x09\x10\x98\x3c\x07\xa5\x69\xff\xdd\x7e\x37\xbb\x82\xdf\x49\xf4\x9d\x37\x35\x9d\x32\xdb\x60\xad\xc1\x7b\x64\x8e\x54\xb2\x2e\xc6\x9f\xb1\x80\x6f\xbf\x85\x05\x15\x16\x7f\x7f\x9e\xcf\xcd\x27\xca\xbe\xb0\xbb\xbd\x0a\xef\x69\x7f\xa1\x73\xb2\xd4\x8f\x1b\x01\x23\x60\x36\x9f\xdf\x7c\x3c\xa2\x6a\x25\x38\xe3\xe9\x84\xac\x9d\x5d\xb7\xc1\xca\xa4\x53\x4e\x1b\x2e\x19\xd7\x54\x0c\xa6\xa4\xcf\x67\x70\xa6\x4a\xa7\xa1\x46\x13\x32\x50\xc9\x41\x01\x2b\xa4\x45\xe8\x34\x61\xec\x6d\x3f\xce\x61\xfc\x8f\x49\x74\xdf\x64\xb6\xf7\xd6\x18\x76\x67\xb7\x42\xa1\xab\x35\xbf\xa4\xaf\x86\x3a\xca\xa8\xc9\xb7\x90\xb7\x8d\xce\x96\xf0\xc3\x2c\x18\x8a\x7d\x27\x78\x99\x12\x02\x99\x6b\xe2\x94\x4a\x2a\x36\x8e\xb3\x61\xfc\x39\x08\x5b\x36\xea\x43\x5a\x7f\x81\x90\x8c\xaa\x84\x5a\xfa\x58\xf4\x13\xd1\xf7\x46\xb3\x59\x58\x9c\xab\x65\xb2\xa1\x63\xaa\x2c\x95\x1c\xec\xe6\x4e\x63\xd4\x73\x28\xf5\xdf\xe0\x94\x1f\xc4\x7f\xee\x2e\x5a\x14\xdc\xa7\x15\x15\xc4\x17\x25\xb4\x8e\xc4\x20\xb5\xc4\xa9\xe0\xce\x23\xdc\x6a\x35\xf9\x2f\x9a\x19\x0e\x5c\x18\x0d\xea\x00\xef\x6d\xf1\x11\x10\xe0\xb0\x26\xf7\x5b\x81\x09\x3c\x4d\x9a\x96\x22\x58\x3e\xd5\x51\xb5\x99\x34\x3f\x49\xac\xe7\x8d\x53\x6a\xb4\x16\xe9\x8e\xb1\xc5\x14\x3b\x32\x5e\x0c\x73\x14\xb8\x46\xa1\x34\x1a\x2c\x29\x17\x31\xec\x6b\xf7\xd5\x10\x30\x82\x68\x23\x2e\xb1\xa1\x04\xc8\x1e\x1a\xa6\xa2\x19\x47\x87\x84\x38\x35\x93\xd6\x78\x46\xf6\xf5\xe9\x32\x5e\xd9\x07\x7d\x0e\xf3\x9b\xef\xdf\x5e\xcd\xe6\xe4\xcd\xf5\x5d\x58\x3d\x39\x2c\x00\x88\x4f\x24\x40\xe8\x26\x87\xdb\x9b\x9f\xae\xdf\x90\xdb\x9b\xef\xde\x5e\x47\x92\x6f\xae\xa8\xb5\x7c\x29\x7d\xc7\xd2\x44\x44\x37\x50\x4f\x0f\xcf\x28\x0b\xad\x78\xab\xdb\x99\x78\x85\x47\xab\xb1\x2c\xc6\xc5\x6e\xe0\xf5\x9e\x73\x9a\x2f\xfd\x9a\x74\xbc\x6d\xc8\xe0\x89\x32\x72\x78\x03\x7a\xfd\xfa\x55\xb4\xa7\xa1\xd2\x06\x42\x54\xd7\xa8\x69\x43\x56\x9f\xc7\x66\x4e\x34\x01\x98\x46\xaa\x9f\x07\xc5\x49\xf9\x1e\x8c\x7f\xd2\xd6\x19\xa4\xe5\x07\x61\xaf\x62\x96\xed\x35\x58\xc9\x4f\x5d\x7c\x28\x36\x9b\x16\x31\x80\x07\x1c\xfa\xfb\x26\x24\x9f\x03\x97\x18\x7e\xf1\x89\x2e\x2c\x78\xfc\xbe\xf4\xf3\xac\x53\x4c\x09\xa2\xb4\x0b\x35\x32\xb6\xa9\x67\x86\xd7\xf3\x88\xf6\xab\x87\x58\xff\xe9\x32\x1d\x54\x5f\x4f\xeb\x19\xa6\x2e\x23\xe2\x53\x2f\x32\x56\x48\x85\x5b\x6d\x88\xa6\x92\x33\xe2\x56\x06\xed\x4a\x89\xe2\xa0\x78\x2f\x28\x8b\x82\xe2\x06\x12\x5e\x57\x5a\x97\x6f\x75\xad\xfb\xad\x5c\x3a\x34\x6b\x2a\x3a\xf3\x58\xb3\x48\xee\xb9\x0b\xe3\x5d\x6b\x83\x54\xc4\x19\xba\x58\x70\x46\x92\x7b\x2b\xd9\x1c\xf7\x70\x50\x38\x18\x20\x41\x7c\xb5\x27\x86\x42\xd9\x3e\xfc\x3e\x22\x8e\x80\x6d\x9a\x5d\xd6\x4a\xb7\x5b\xbe\x80\xec\xc3\xfc\x2e\x7b\xc3\xcd\x6e\xf7\x22\x44\x2c\xab\xac\x53\x25\xdc\xdd\xcd\xe1\xf0\xd4\x09\x4e\xf5\x66\xec\x74\x32\xc3\xff\x49\x36\xd7\xf1\xe2\x84\x6d\xa6\x8b\x76\x2c\x86\x65\x34\x8e\x2f\x7c\x5d\x43\x9b\x77\xfb\xc7\x16\x29\xbe\x62\x47\x60\x98\xdf\x65\x57\xa6\x0f\x83\xda\xf0\xb5\xe7\x7b\xc0\xcd\x9e\xeb\x3d\x6e\x76\xbb\xed\x16\x65\x71\x0e\x74\xbc\xfb\xf8\xfe\x0e\x9a\x97\x84\x1e\x6c\x1c\x3d\x1a\xfc\x4f\x55\xb1\xe1\x97\x8d\x5f\x1d\x5e\xfa\x2f\x37\xbf\x89\xd2\xd5\xb9\xf1\xbf\x03\x00\x00\xff\xff\x25\x3c\x40\x2a\x79\x1a\x00\x00"

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

	info := bindataFileInfo{name: "native/envoy-config.yaml", size: 6777, mode: os.FileMode(416), modTime: time.Unix(1598032701, 0)}
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
