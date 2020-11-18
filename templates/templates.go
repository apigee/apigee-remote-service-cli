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

var _istio16ApigeeEnvoyAdapterYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xbc\x56\xcd\x6e\xe3\x36\x10\xbe\xfb\x29\x88\xdc\xe9\x9f\xb6\x7b\x88\x80\x3d\x04\xdb\x45\x1a\xa0\xce\x1a\x4d\xda\x3b\x43\x8d\x25\xa2\x24\x87\x25\x47\x6a\x55\x41\xef\x5e\x50\x94\x6d\x29\xb1\x6a\x37\x08\xea\x8b\xac\xf9\xfd\x38\xf3\x8d\x38\xc2\xa9\xdf\xc0\x07\x85\x36\x63\xc2\xb9\xb0\xaa\x37\x8b\xdf\x95\xcd\x33\xf6\x23\x38\x8d\x8d\x01\x4b\x0b\x03\x24\x72\x41\x22\x5b\x30\x66\x85\x81\x68\xaa\x0a\x00\xee\xc1\x20\x01\x0f\xe0\x6b\x25\x81\x83\xad\xb1\x19\x6c\x82\x13\x12\x32\xd6\xb6\xcb\xc7\xc3\x5b\xd7\x2d\x82\x03\x19\xa3\x78\x70\x5a\x49\x11\x32\xb6\x59\x30\x16\x40\x83\x24\xf4\x51\xc3\x98\x11\x24\xcb\x9f\xc5\x0b\xe8\x90\x04\x2c\x22\xbb\x94\x93\xc0\x38\x2d\x08\x86\x18\x23\xc4\x7d\x00\x6b\x91\x04\x29\xb4\xc7\x98\x8c\x05\x95\x83\x14\x7e\xa9\x02\x29\x5c\x2a\x5c\x79\xf8\xd3\x2b\x82\x3b\xe7\x7e\x7a\x7e\xde\xed\x3c\xbe\x80\x0f\x19\xbb\x21\x5f\xc1\xcd\xd1\xcd\x79\x34\x40\x25\x54\x21\xfa\x38\x41\x65\xc6\x56\x06\xc8\x2b\x19\xe6\x8c\xd0\x53\xc6\x6e\x3e\xad\xd7\x9b\xb9\x38\x41\x96\x10\x2b\x5b\x12\xb9\xb9\x30\x41\x7a\xe1\xe0\x02\x20\x6a\xa2\xc9\x49\x16\x4b\x3e\x98\xea\x49\x51\xaf\x2a\x6b\xfa\xd5\x07\x8a\xd4\x9b\x5e\x76\x68\x63\xff\x3f\x79\xdc\x49\x89\x95\xa5\xc7\x2b\xe8\x91\xbc\x64\xe5\x15\x35\x5f\xd0\x12\xfc\x45\x19\x63\xc7\x64\xbe\xb2\x77\xe1\xd7\x00\x3e\x63\xb7\xb7\xb7\x53\xf1\xbd\xc7\xca\x9d\x91\x3f\xa2\xfd\x05\x91\x32\x16\x2b\x33\xa8\x24\x5a\x12\xca\xc6\x16\x0e\x12\x7e\x15\x7b\xd3\x4f\x19\x51\xc4\x52\x17\x88\x85\x86\xd5\xe0\xd2\xdb\x70\x91\x0b\x47\xe0\xb3\xb6\x5d\x3e\x44\xb3\x67\x51\x74\xdd\xcd\xd4\x75\x57\x69\xbd\x43\xad\x64\x93\xb1\x87\xfd\x23\xd2\xce\x43\x88\xc3\x74\xec\x1a\x7a\x1a\xf5\x82\x9f\xf0\xee\x7a\xb6\x7c\x5a\xaf\xd7\x47\xad\x56\x35\x58\x08\xa1\xe7\xe4\xc9\x89\xf5\x74\xb9\x07\x1a\x8b\x18\x1b\x38\x59\x82\xd0\x54\xfe\x3d\x55\x1d\x62\x6f\x46\xe2\xbd\x50\xba\xf2\xf0\x5c\x7a\x08\x25\xea\x3c\x4d\xe5\xd1\x05\xbc\xc2\xfc\x09\x24\xda\x3c\x0e\xec\x09\x95\x07\x91\xab\xff\x13\xd6\xf7\xeb\xab\x70\x09\x5f\x84\x71\x6a\xce\x38\xd7\x58\x70\x0d\x35\xe8\xcf\x39\xbc\x54\xc5\x2b\xad\x44\xbb\x57\xc5\xe7\x55\x7a\x0e\x8f\x65\x23\x8c\x1e\x1d\x36\x60\xe5\x25\x4c\x22\x6b\x65\x14\x85\xe9\x31\xa5\xab\x22\x9a\xb5\x99\x48\x0d\x18\xf4\x4d\xaf\xd8\xaa\x91\xc6\xc3\x1f\x15\x84\x99\x18\xd7\x84\xa8\x51\x57\x06\xb6\x71\xf8\x26\x74\x32\x51\xb2\x4b\x25\x4f\xe7\x19\x05\xbb\x7e\x0e\x52\x97\xbf\x59\xdd\x0c\xc3\xd5\xb6\x9c\xa9\x3d\x5b\x3e\x84\xfb\x2f\xbb\xad\xb0\xa2\x80\xbc\xeb\x16\x8c\x1d\x14\x77\x56\xe8\x86\x94\x0c\x4f\x20\x3d\x50\xaf\x3b\x07\x4a\x1c\xec\x78\xe8\x0d\xdf\xc2\x9b\x37\x78\x85\x29\x25\x07\x1d\xa0\x47\xf0\xd5\x4a\xcc\x21\x8f\xdf\xa2\xd9\xec\xe8\x68\x18\xea\x15\xe9\xf0\x26\x37\xe9\xc0\x53\x65\x2f\x66\xb5\xf9\x6c\x12\xd7\x7f\x00\xe6\xce\x37\xa7\x3d\x53\xf0\x71\x92\x04\xeb\x5d\x1f\xb5\xc4\x83\xad\x70\xd9\x7f\xe2\xc2\xbb\x5b\xce\x2f\x75\x32\xbd\x8e\xd1\xe4\xb0\x17\x95\xa6\x2d\xe6\x90\xb1\x1f\xbe\x1b\x0f\x7c\x32\x4e\x37\x4c\xdb\x2e\xbf\xf9\xa2\xeb\x78\xdb\x2e\xbf\xda\xba\xeb\xf8\x99\x1c\x17\x49\xc1\xe7\xbb\xfd\x6e\x64\x43\x21\xab\x5c\x8a\x04\x6e\x94\x96\x27\xaa\xbd\xee\x28\xff\x57\x42\x7c\x60\x8d\xa6\x09\x4e\x30\x38\xe7\x8b\xf1\x26\x78\x5c\x02\x9f\x12\x0f\x3e\x70\x03\x9c\x6e\x21\x17\x37\x90\xc3\xa6\x71\xbc\x2d\xf9\xe9\xae\x48\xe7\x4e\x70\x0a\xef\xe4\x9b\x4d\xf2\x52\xf4\x7f\x02\x00\x00\xff\xff\xe5\x85\x92\x0a\xfd\x0a\x00\x00"

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

	info := bindataFileInfo{name: "istio-1.6/apigee-envoy-adapter.yaml", size: 2813, mode: os.FileMode(416), modTime: time.Unix(1605730179, 0)}
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

	info := bindataFileInfo{name: "istio-1.6/envoyfilter-sidecar.yaml", size: 2759, mode: os.FileMode(416), modTime: time.Unix(1605730179, 0)}
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

	info := bindataFileInfo{name: "istio-1.6/httpbin.yaml", size: 704, mode: os.FileMode(416), modTime: time.Unix(1605730179, 0)}
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

	info := bindataFileInfo{name: "istio-1.6/request-authentication.yaml", size: 838, mode: os.FileMode(416), modTime: time.Unix(1605730179, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio17ApigeeEnvoyAdapterYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xbc\x56\xcd\x6e\xe3\x36\x10\xbe\xfb\x29\x88\xdc\xe9\x9f\xb6\x7b\x88\x80\x3d\x04\xdb\x45\x1a\xa0\xce\x1a\x4d\xda\x3b\x43\x8d\x25\xa2\x24\x87\x25\x47\x6a\x55\x41\xef\x5e\x50\x94\x6d\x29\xb1\x6a\x37\x08\xea\x8b\xac\xf9\xfd\x38\xf3\x8d\x38\xc2\xa9\xdf\xc0\x07\x85\x36\x63\xc2\xb9\xb0\xaa\x37\x8b\xdf\x95\xcd\x33\xf6\x23\x38\x8d\x8d\x01\x4b\x0b\x03\x24\x72\x41\x22\x5b\x30\x66\x85\x81\x68\xaa\x0a\x00\xee\xc1\x20\x01\x0f\xe0\x6b\x25\x81\x83\xad\xb1\x19\x6c\x82\x13\x12\x32\xd6\xb6\xcb\xc7\xc3\x5b\xd7\x2d\x82\x03\x19\xa3\x78\x70\x5a\x49\x11\x32\xb6\x59\x30\x16\x40\x83\x24\xf4\x51\xc3\x98\x11\x24\xcb\x9f\xc5\x0b\xe8\x90\x04\x2c\x22\xbb\x94\x93\xc0\x38\x2d\x08\x86\x18\x23\xc4\x7d\x00\x6b\x91\x04\x29\xb4\xc7\x98\x8c\x05\x95\x83\x14\x7e\xa9\x02\x29\x5c\x2a\x5c\x79\xf8\xd3\x2b\x82\x3b\xe7\x7e\x7a\x7e\xde\xed\x3c\xbe\x80\x0f\x19\xbb\x21\x5f\xc1\xcd\xd1\xcd\x79\x34\x40\x25\x54\x21\xfa\x38\x41\x65\xc6\x56\x06\xc8\x2b\x19\xe6\x8c\xd0\x53\xc6\x6e\x3e\xad\xd7\x9b\xb9\x38\x41\x96\x10\x2b\x5b\x12\xb9\xb9\x30\x41\x7a\xe1\xe0\x02\x20\x6a\xa2\xc9\x49\x16\x4b\x3e\x98\xea\x49\x51\xaf\x2a\x6b\xfa\xd5\x07\x8a\xd4\x9b\x5e\x76\x68\x63\xff\x3f\x79\xdc\x49\x89\x95\xa5\xc7\x2b\xe8\x91\xbc\x64\xe5\x15\x35\x5f\xd0\x12\xfc\x45\x19\x63\xc7\x64\xbe\xb2\x77\xe1\xd7\x00\x3e\x63\xb7\xb7\xb7\x53\xf1\xbd\xc7\xca\x9d\x91\x3f\xa2\xfd\x05\x91\x32\x16\x2b\x33\xa8\x24\x5a\x12\xca\xc6\x16\x0e\x12\x7e\x15\x7b\xd3\x4f\x19\x51\xc4\x52\x17\x88\x85\x86\xd5\xe0\xd2\xdb\x70\x91\x0b\x47\xe0\xb3\xb6\x5d\x3e\x44\xb3\x67\x51\x74\xdd\xcd\xd4\x75\x57\x69\xbd\x43\xad\x64\x93\xb1\x87\xfd\x23\xd2\xce\x43\x88\xc3\x74\xec\x1a\x7a\x1a\xf5\x82\x9f\xf0\xee\x7a\xb6\x7c\x5a\xaf\xd7\x47\xad\x56\x35\x58\x08\xa1\xe7\xe4\xc9\x89\xf5\x74\xb9\x07\x1a\x8b\x18\x1b\x38\x59\x82\xd0\x54\xfe\x3d\x55\x1d\x62\x6f\x46\xe2\xbd\x50\xba\xf2\xf0\x5c\x7a\x08\x25\xea\x3c\x4d\xe5\xd1\x05\xbc\xc2\xfc\x09\x24\xda\x3c\x0e\xec\x09\x95\x07\x91\xab\xff\x13\xd6\xf7\xeb\xab\x70\x09\x5f\x84\x71\x6a\xce\x38\xd7\x58\x70\x0d\x35\xe8\xcf\x39\xbc\x54\xc5\x2b\xad\x44\xbb\x57\xc5\xe7\x55\x7a\x0e\x8f\x65\x23\x8c\x1e\x1d\x36\x60\xe5\x25\x4c\x22\x6b\x65\x14\x85\xe9\x31\xa5\xab\x22\x9a\xb5\x99\x48\x0d\x18\xf4\x4d\xaf\xd8\xaa\x91\xc6\xc3\x1f\x15\x84\x99\x18\xd7\x84\xa8\x51\x57\x06\xb6\x71\xf8\x26\x74\x32\x51\xb2\x4b\x25\x4f\xe7\x19\x05\xbb\x7e\x0e\x52\x97\xbf\x59\xdd\x0c\xc3\xd5\xb6\x9c\xa9\x3d\x5b\x3e\x84\xfb\x2f\xbb\xad\xb0\xa2\x80\xbc\xeb\x16\x8c\x1d\x14\x77\x56\xe8\x86\x94\x0c\x4f\x20\x3d\x50\xaf\x3b\x07\x4a\x1c\xec\x78\xe8\x0d\xdf\xc2\x9b\x37\x78\x85\x29\x25\x07\x1d\xa0\x47\xf0\xd5\x4a\xcc\x21\x8f\xdf\xa2\xd9\xec\xe8\x68\x18\xea\x15\xe9\xf0\x26\x37\xe9\xc0\x53\x65\x2f\x66\xb5\xf9\x6c\x12\xd7\x7f\x00\xe6\xce\x37\xa7\x3d\x53\xf0\x71\x92\x04\xeb\x5d\x1f\xb5\xc4\x83\xad\x70\xd9\x7f\xe2\xc2\xbb\x5b\xce\x2f\x75\x32\xbd\x8e\xd1\xe4\xb0\x17\x95\xa6\x2d\xe6\x90\xb1\x1f\xbe\x1b\x0f\x7c\x32\x4e\x37\x4c\xdb\x2e\xbf\xf9\xa2\xeb\x78\xdb\x2e\xbf\xda\xba\xeb\xf8\x99\x1c\x17\x49\xc1\xe7\xbb\xfd\x6e\x64\x43\x21\xab\x5c\x8a\x04\x6e\x94\x96\x27\xaa\xbd\xee\x28\xff\x57\x42\x7c\x60\x8d\xa6\x09\x4e\x30\x38\xe7\x8b\xf1\x26\x78\x5c\x02\x9f\x12\x0f\x3e\x70\x03\x9c\x6e\x21\x17\x37\x90\xc3\xa6\x71\xbc\x2d\xf9\xe9\xae\x48\xe7\x4e\x70\x0a\xef\xe4\x9b\x4d\xf2\x52\xf4\x7f\x02\x00\x00\xff\xff\xe5\x85\x92\x0a\xfd\x0a\x00\x00"

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

	info := bindataFileInfo{name: "istio-1.7/apigee-envoy-adapter.yaml", size: 2813, mode: os.FileMode(416), modTime: time.Unix(1605730179, 0)}
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

	info := bindataFileInfo{name: "istio-1.7/envoyfilter-sidecar.yaml", size: 3049, mode: os.FileMode(416), modTime: time.Unix(1605730179, 0)}
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

	info := bindataFileInfo{name: "istio-1.7/httpbin.yaml", size: 704, mode: os.FileMode(416), modTime: time.Unix(1605730179, 0)}
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

	info := bindataFileInfo{name: "istio-1.7/request-authentication.yaml", size: 838, mode: os.FileMode(416), modTime: time.Unix(1605730179, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _nativeEnvoyConfigYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xe4\x58\x6f\x6f\xdb\xbc\x11\x7f\x9f\x4f\x71\x70\xdf\x6c\x43\xad\x38\x49\x8b\x75\x02\x0a\xcc\x4d\x87\xfe\xf3\x92\x21\x49\xd7\xed\x15\xc1\x52\x67\x9b\x09\x45\x6a\xe4\xc9\x89\x6b\xf8\xbb\x0f\x24\x25\x5b\x92\xe5\xc4\xc5\xd3\x02\x7d\xf0\xf8\x9d\x79\xff\xc8\xbb\xdf\xfd\x78\x14\xcf\x72\xa9\xd3\x23\x00\x2e\x04\x3a\xc7\x94\x99\xb1\x82\xd3\x3c\x85\x63\xca\x8b\x63\xd4\x0b\xb3\x64\x41\x29\x51\x66\xe6\xf5\xb2\xcc\xa2\x73\xde\x04\xc0\x19\x71\x87\xc4\x5a\x6b\x5b\x15\x38\x39\xfd\x6b\x32\x4a\x46\xc9\x49\x25\x28\x8c\x25\xb6\xe0\xaa\xc4\x14\xfe\x36\x1a\x8d\x8e\x00\x8e\x1c\x71\x92\x82\x59\x74\xa6\xb4\x02\x83\x13\x25\x1d\xa1\x46\x1b\xfe\x0c\xa1\xe3\xbe\x13\x14\x56\xdb\x80\xa3\x10\x6e\xf4\xbc\x15\xe9\xd5\xe8\xd5\x08\xd6\x3e\x96\xb7\x9e\x4a\x45\x68\x99\x98\x73\xa9\x2b\x97\xc3\x6a\x71\x13\x61\x08\x9a\xe7\x98\x42\x38\x7d\x52\x09\x13\x8d\x74\x6f\xec\x5d\x32\x27\x2a\x98\x30\x5a\xa3\x20\x69\x34\xcb\xb9\xe6\x33\xb4\x95\x2d\x00\x2d\x0b\xcc\xbc\xc2\x54\xce\xd2\x2a\x6a\xfc\x0d\xfe\xee\x65\x83\x34\xa8\x24\x33\x63\x66\x0a\x79\x21\x5d\x22\x4c\x1e\x53\x9d\xe0\x03\xa1\x76\xd2\x68\x77\x68\xdc\x64\x71\x96\xbc\x27\x2a\xce\x37\x92\x7f\x76\x36\x04\xe0\x93\xcc\x0a\x8b\x53\xf9\x90\x82\xd4\x33\x9f\x2d\xe6\xfd\x35\x74\xac\x29\x09\xeb\x6d\x37\xd6\x01\x16\xd2\x52\xc9\x15\x9b\x1b\x47\xae\x2d\xaa\x33\x95\xe1\x94\x97\x8a\x5a\x32\x80\xcc\xe4\x21\xcb\x30\xf8\xcb\xa0\x23\x0a\xd1\x3a\xce\xbc\xbb\x9c\x93\x98\xfb\x9a\xd6\xbb\x3d\x0e\xa5\xeb\x31\xee\xda\xfa\x9f\x50\xa5\x23\xb4\x29\xac\x56\xc9\x0d\xb7\x33\xa4\x6b\xb4\x0b\x29\x30\xb9\xe0\x39\xae\x77\x3d\x35\x16\x42\x7a\x1b\x40\x68\x88\x9e\x01\x7a\x2c\x71\x42\xf8\xf8\xe5\x06\xc8\xdc\xa1\x76\xcf\x81\x2b\x65\xee\x59\x2e\x9d\x93\x7a\x16\xff\x39\x18\xff\xeb\x03\x7c\xc2\x25\x70\xe5\xcc\xd1\x6e\xa2\xda\x90\xf2\x31\x93\xdb\x7b\x62\xbc\xa4\xb9\x6e\xed\xae\x8d\xa2\xce\xc6\x0f\x00\x52\xb4\xac\x22\x75\x02\x25\x8b\x53\xae\x8a\x39\x4f\x3e\xde\xd3\xb8\xa4\x39\x6a\x92\x82\x7b\xe8\x74\xe2\x14\xd6\x2c\x64\xd6\xe8\x8c\xed\x8f\x17\x72\x86\xbd\x45\x90\xce\x95\xbe\x06\x3e\xa6\x4b\x8f\x8f\x57\xab\xe4\xaa\xd4\x24\x73\x7c\x6f\x1c\xad\xd7\xc7\x16\x73\x43\x38\x74\xb1\x34\xc7\x21\x9d\x3d\x7e\x78\x99\x49\xd4\x62\x17\x25\x31\x9f\x6d\x2f\x43\xa1\x24\xea\x2e\x00\xfd\x2f\xea\xb1\xdb\xfb\xbb\x5e\x47\x55\xe1\x4b\x2b\xfb\xa5\x00\x5e\x74\xf0\x61\x04\x5a\x72\x7b\x1c\x6d\xd0\x19\x73\x37\xf4\xb5\xa8\x0d\xf7\x98\xf8\x40\xa6\xa4\x14\x5e\xf6\x3b\x15\x5c\xcc\x91\x65\xa5\x0d\xd5\xdb\x77\x02\x87\xc2\xe8\xcc\xa5\x70\x16\x38\xb7\xfb\x2b\xf8\x52\x19\x9e\x31\xa9\x59\x8e\xc4\x33\x4e\xbc\xde\x63\xb7\x6b\x4b\xb5\xbf\x69\xfb\x3c\xd7\x4d\xbc\xdb\xc2\xf8\xbf\x52\xda\xfe\xda\xd6\x32\xc6\xf5\xb2\xff\x48\x95\x46\x8e\xba\x4b\x48\xdb\x4d\xd5\xd8\x65\xb1\xf1\x7a\xcf\x53\xeb\xb6\x3a\x39\x85\xd5\x7a\x6f\xff\x8f\x83\x9b\x98\x88\xc3\xda\x1b\x1f\x62\xd7\x7d\xdb\xdf\xde\x3f\xa4\xbb\x37\x71\x92\xc5\x69\xf2\x8f\x87\xd0\xd8\xdf\x3a\x9e\x67\xb6\x10\xac\x42\xdc\x6e\xde\xe2\x65\xef\x75\x1e\xe1\xd6\x56\x3a\x87\x9d\x26\x0c\x1e\x76\x6c\x37\x20\x3e\x71\x5d\x51\x47\xb7\x86\x9f\x4f\x0c\xf9\x03\xf9\x60\xae\xe0\x3d\x24\x30\x7c\x8a\x4a\xfb\xeb\x77\xf5\x66\x7c\x0e\x7f\xd2\xe8\x87\x1d\x6e\x97\x30\x35\xb6\xae\x69\xcd\xb5\x16\x6f\x51\x10\x2b\xb5\xf7\x64\xac\xfc\x86\x19\xbc\x7e\x0d\x53\xae\x1c\xfe\xf9\xb0\x9a\xdb\xaf\x5c\xfc\xe4\x72\xfb\x10\xbe\xd2\xfe\x40\x87\x74\xa9\x9f\xf0\x02\x47\xc0\x78\x32\xb9\xfc\xb2\x23\x2d\x8c\x92\x42\xf6\x37\x64\x55\xec\x6a\xf6\x30\xb6\xbf\xe5\x0a\x2b\xb5\x90\x05\x57\x7b\x5b\xd2\xf7\x33\x90\x2d\xfb\xdb\xb0\x40\x1b\x3a\xd0\xe8\xbd\x0e\xe6\xc8\xb3\x70\xbd\xc3\xc0\xe7\x7e\x90\xc2\xe0\x3f\xc3\x58\xbe\xe1\x78\x53\xad\x01\x74\xfa\xf7\xb1\x4a\xf9\x51\xc2\xfe\xc8\x5a\xf5\x4c\x70\x8d\x48\x7e\x5a\xbb\xaa\x63\x36\x9c\x6f\xc7\xef\x70\xd9\xb7\xc0\x2b\x8c\x52\x28\xa8\xc6\x29\xd7\x5c\x2d\x49\x8a\xfd\xfc\xb3\x75\x36\xab\xc3\x87\xb6\xfe\x09\x90\x8c\xa1\x94\x99\x79\x2c\xfa\x31\xf4\x9d\x2d\xc4\x38\x2c\x4e\xcc\xec\x3c\x28\x75\x9c\x0b\x93\xe7\x46\xef\x89\xfc\x14\x47\x3d\xc5\x52\xbf\x85\xa7\xfc\xdb\xe7\x7b\xad\x78\x96\x49\xdf\x56\x5c\x31\x7f\x29\xa1\x23\x16\x41\xea\x18\x99\x50\xce\x1d\xde\x4a\x2b\x5e\xa1\x25\x3c\xab\x07\x67\xa0\x30\xad\x56\x00\xef\x98\x78\x04\x04\x3a\xac\xc4\xdd\x51\x60\x08\x0f\xc3\x7a\xa4\x08\x99\xef\x9b\xa8\x9a\x4a\x85\x7c\x54\x58\x58\x93\x95\x62\x67\x8c\x69\x29\x15\xaa\x7f\x62\x6c\x28\xc5\x89\x4c\x66\xfb\x35\x32\x5c\xa0\x32\x05\x5a\xcc\xb9\x54\x11\xf6\x55\xf9\x2a\x0a\x38\x82\x98\x23\xa9\xb1\x96\x04\xca\xde\x99\xef\xe3\x34\x56\xa5\xf1\x68\xdb\x10\x8f\x3d\x04\x2a\x3e\x63\x9b\xfb\xe9\x34\x1e\xd9\x83\x3e\x85\xc9\xe5\xbb\x0f\xe7\xe3\x09\x7b\x7b\x71\x1d\x56\x33\xed\x3b\xca\xdc\x95\x05\x9b\xf2\x5c\xaa\x65\x0a\xff\x7e\xc1\x2e\x2f\x26\xff\x0d\x62\xf5\x95\x05\x0a\x5d\xa6\x70\x75\xf9\xf9\xe2\x2d\xbb\xba\x7c\xf3\xe1\x22\x8a\xfc\x70\xc5\x9d\x93\x33\xed\x27\x96\x1a\x11\x6d\xa0\x3e\xfe\x62\x41\x9d\x15\x46\x36\xa6\x9d\xa1\x0f\xb8\xb3\x1a\xaf\xc5\xb8\xd8\x06\x5e\xe7\x0d\x5d\xff\xfa\x1f\xf0\xbb\x66\x30\xd8\x93\xf1\xee\xbb\xae\xfd\xc8\x7f\xf1\xe2\x2c\x66\xd4\x72\xed\x82\x20\x06\xac\x03\x35\x49\xab\xab\xe3\x12\x52\x35\x04\xfb\xb9\xea\xfb\xc8\xb8\xd7\xbf\xa7\xe3\xcf\x85\x23\x8b\x3c\xbf\x51\xee\x3c\xf6\xd9\x26\x82\xd3\xf2\xf1\xa3\xef\xc3\x67\x3d\x26\x06\x02\x81\xed\x8c\x5f\xc3\xf2\x29\x82\xe9\x87\xa0\x27\xf2\x53\x56\x58\x43\x46\x18\xc5\x4c\x41\xe1\xb2\x8c\xf3\xea\x81\x38\x7b\x9a\xda\x7e\x09\xac\x8d\x33\x5e\x10\xda\x43\x40\xf6\x72\x54\xbd\x6a\xaa\x8b\x45\x7d\xed\x20\x65\x8e\x5c\xd1\x7c\xc9\x0a\xae\xa5\x60\x34\xb7\xe8\xe6\x46\x65\xdb\x1d\x6c\x1c\x25\xd1\x51\x34\x60\x62\x8e\xe2\xae\x91\x85\xc6\x1c\xbb\x31\x95\x9a\xd0\x2e\xb8\x6a\xbd\xd0\xea\x45\x76\x2b\x29\x3c\xf8\x1a\x06\xda\x30\xb2\x7c\x3a\x95\x82\xf5\xda\x96\xba\xde\xee\x76\xa3\x70\xb2\x11\xf7\x08\xcf\x36\xc2\x70\x75\x36\x37\xbf\x81\xc6\x0e\xd5\x8d\x92\xd3\x2a\xe8\x6a\x25\xa7\x90\xdc\x4c\xae\x93\xb7\xd2\xae\xd7\xcf\x02\x7e\x45\xe9\xc8\xe4\x70\x7d\x3d\x81\xed\x17\x27\x20\xd3\x79\x75\xf7\x37\x37\xfc\x4e\xba\xbb\xc2\x0b\x29\x57\xbf\x37\x9a\xa0\x0c\xcb\x68\x49\x4e\xfd\x4d\x87\x2e\x6d\x4f\x94\x0d\x51\xfc\x98\x18\x29\x7c\x72\x9d\x9c\x5b\xea\x7c\x69\x2a\xac\x5c\x78\xbd\x3b\x5c\x6e\xb4\x3e\xe1\x72\xbd\x5e\xad\x50\x67\xeb\xf5\xd3\x44\xf2\xf1\xcb\xa7\x6b\xa8\xbf\x2d\x74\x48\x64\xe7\x33\xc2\x2f\x75\xaf\xed\xff\xd6\xf1\x4b\xf0\x4c\xeb\x63\xce\x1f\xe4\x32\x6b\x9f\xf9\xff\x01\x00\x00\xff\xff\x7b\x2e\xb2\x23\x02\x18\x00\x00"

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

	info := bindataFileInfo{name: "native/envoy-config.yaml", size: 6146, mode: os.FileMode(416), modTime: time.Unix(1605730179, 0)}
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
