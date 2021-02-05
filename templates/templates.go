// Code generated by go-bindata. (@generated) DO NOT EDIT.

 //Package templates generated by go-bindata.// sources:
// templates/envoy-1.16/envoy-config.yaml
// templates/istio-1.7/apigee-envoy-adapter.yaml
// templates/istio-1.7/envoyfilter-sidecar.yaml
// templates/istio-1.7/httpbin.yaml
// templates/istio-1.7/request-authentication.yaml
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
		return nil, fmt.Errorf("read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("read %q: %v", name, err)
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

// ModTime return file modify time
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

var _envoy116EnvoyConfigYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xd4\x58\x5f\x6f\x23\xb7\x11\x7f\xf7\xa7\x18\xe8\x5e\xda\x22\x5a\xeb\xee\x1c\xf4\xba\x40\x80\x2a\xbe\x22\x39\x9f\x6a\x1f\x2c\x27\x6e\x9f\x08\x1e\x77\x24\xd1\xe6\x92\x5b\x72\x56\xb6\x4e\xd0\x77\x2f\xc8\xfd\xa7\x5d\xed\xca\x4a\x9b\x04\x17\xbd\x89\x33\x9c\x99\x9d\xf9\xcd\x8f\x43\xf2\x24\x95\x3a\x3e\x03\xe0\x42\xa0\x73\x4c\x99\x25\xcb\x38\xad\x62\x38\xa7\x34\x3b\x47\xbd\x36\x1b\x16\x94\x22\x65\x96\x5e\x2f\x49\x2c\x3a\xe7\xb7\x00\x38\x23\x1e\x91\x58\x6b\xad\x51\x81\xd7\x6f\xfe\x1a\x4d\xa2\x49\xf4\xba\x14\x64\xc6\x12\x5b\x73\x95\x63\x0c\x7f\x9b\x4c\x26\x67\x67\x8e\x38\x49\xc1\x2c\x3a\x93\x5b\x81\xc1\x84\x92\x8e\x50\xa3\x0d\x7f\xc6\xd0\x31\xde\x71\x09\xdb\xc6\xdd\x24\x38\x9b\x7c\xd3\xf2\xf3\x6e\xf2\x6e\x02\xbb\xb3\xb0\x7b\x21\x15\xa1\x65\x62\xc5\xa5\x2e\x0d\x8e\xcb\xc5\xda\xfe\x18\x34\x4f\x31\x86\xf0\xe5\x51\x29\x8c\x34\xd2\x93\xb1\x8f\xd1\x8a\x28\x63\xc2\x68\x8d\x82\xa4\xd1\x2c\xe5\x9a\x2f\xd1\x96\x7b\x01\x68\x93\x61\xe2\x15\x16\x72\x19\x03\xd4\xeb\x00\xa3\xbf\x7b\xd9\x28\x0e\x2a\xd1\xd2\x98\xa5\x42\x9e\x49\x17\x09\x93\x16\x69\x8e\xf0\x99\x50\x3b\x69\xb4\x3b\xd5\x6f\xb4\x7e\x1b\xfd\x48\x94\x5d\xd6\x92\x7f\x76\x02\x02\xf0\x29\x66\x99\xc5\x85\x7c\x8e\x41\xea\xa5\xcf\x15\xf3\xf6\xf6\x74\xac\xc9\x09\xab\xb0\xf7\xd6\x01\xd6\xd2\x52\xce\x15\x5b\x19\x47\xae\x2d\xaa\x32\x95\xe0\x82\xe7\x8a\x5a\x32\x80\xc4\xa4\x21\xcb\x30\xfa\xcb\xa8\x23\x0a\xde\x3a\xc6\xbc\xb9\x94\x93\x58\xf9\x8a\x56\xd1\x9e\xc3\xae\xa3\x54\x6e\xee\xee\xf5\x3f\xa1\x72\x47\x68\x63\xd8\x6e\xa3\x3b\x6e\x97\x48\x73\xb4\x6b\x29\x30\xba\xe6\x29\xee\x4a\x08\x14\xbf\x90\xce\xba\xf0\x7b\x82\x57\x80\x1e\x37\x9c\x10\xae\xee\xef\x80\xcc\x23\x6a\xf7\x0d\x70\xa5\xcc\x13\x4b\xa5\x73\x52\x2f\x8b\x7f\x0e\xa6\x9f\x3e\xc0\x47\xdc\x00\x57\xce\x9c\x1d\xa6\xa5\x0d\x20\xef\x31\x7a\x78\x22\xc6\x73\x5a\xe9\x56\xf8\x6d\xcc\x74\xbe\xec\x7f\x83\x4d\xdb\x9b\x47\xc9\xd5\x13\x4d\x73\x5a\xa1\x26\x29\xb8\x07\x4a\xc7\x4f\x66\xcd\x5a\x26\x7b\x7d\xd0\xfc\x78\x26\x97\xd8\x9b\x72\xe9\x5c\x5e\x66\xfc\xea\xfe\xee\x53\x69\xe2\x23\x6e\x76\x87\x75\x03\xe0\x79\x22\x51\x8b\xc3\xca\x17\x59\xb3\x98\x1a\xc2\xb1\x2b\x8a\x36\x16\x4a\xa2\xee\x82\xca\xff\x0a\x3d\xf6\xf0\xf4\xd8\x6b\xa8\x2c\x6e\x6e\x65\xbf\x74\xbb\x1d\x83\x5c\x40\x74\x9b\x6b\x92\x29\xde\xcd\xe6\xbd\xc1\xfa\x9f\xb7\x11\xac\xb9\xf8\xfc\x7c\xbb\xad\xb6\xfc\x68\x1c\xed\x76\xdb\xad\x5c\x80\xc6\xda\xd0\x27\x63\x09\x46\x17\x17\x6f\x47\xbb\x5d\xdc\x28\xfb\x65\xaf\x8c\x3a\xd9\xed\xce\xcb\x6f\x0c\xb0\x3a\x17\x68\xc9\x0d\xc6\x88\xca\xe1\xcb\x91\x9d\x1c\xd8\xbb\xc9\xaf\x15\x97\xdf\x30\x10\x56\xdd\x82\x05\x64\xc6\x1e\x7d\x55\x41\x07\xb6\xf8\x58\x4c\x4e\x31\x7c\xdb\xef\x52\x70\xb1\x42\x96\xe4\x36\x80\xb6\xbf\xa4\x00\x0e\x85\xd1\x89\x8b\xe1\xed\x64\xd2\xa3\x92\xf1\x8d\x32\x3c\x61\x52\xb3\x14\x89\x27\x9c\xf8\x29\xa0\xb5\xb9\x1a\xa6\xa9\x3e\x37\x15\x6d\x1d\x92\x16\xfe\x27\x97\xb6\x1f\xf9\x95\x8c\x71\xbd\xe9\xff\xbe\x52\x23\x45\xdd\xa5\xe0\x26\xa8\xaa\x7f\x59\x41\x3e\x45\x01\x06\x74\x5b\x6c\x16\xc3\x76\x37\xc0\x80\xd3\x60\xa4\x48\xc3\x69\x04\x87\xcf\x05\xe5\x7c\x19\x26\xb8\x5f\x8f\xdf\x6a\x67\x9e\xdf\xfe\xf1\x1c\xf8\xed\x4b\xc7\x3c\x59\xae\x5d\x18\x07\x78\x26\xd9\x1a\xad\xb7\x13\xc3\xcf\x6f\x3b\x7a\x4b\x9b\x09\x56\x22\xf5\x30\xc5\xc5\x14\xe4\x75\x8e\x1c\x3c\xad\xcc\x8f\x3b\x6c\x16\x2c\x1c\xec\xad\xc1\xff\xba\x0b\xfe\x0a\xa6\x3e\x6b\xe4\x3f\xd4\x1b\x77\x19\xef\x61\xcf\xf1\xf1\x93\xa6\xbf\xb4\xb7\xdf\x4f\x2f\xe1\x4f\x1a\xfd\xcc\xc7\xed\x06\x16\xc6\x56\xe5\xae\x0e\x22\x8b\x0f\x28\x88\xe5\xda\xdb\x31\x56\x7e\xc1\x04\xbe\xfb\x0e\x16\x5c\x39\xfc\xf3\x69\x70\xb0\x9f\xb9\xf8\x3d\x90\xe0\xfd\x78\x10\xf8\xaf\x3a\xa5\x87\xfd\xb4\x1b\xe8\x04\xa6\xb3\xd9\xcd\xfd\x81\x34\x33\x4a\x0a\xd9\xdf\xae\x65\x7d\xcb\x59\xcc\xd8\xfe\x86\xcc\xac\xd4\x42\x66\x5c\x0d\x36\xac\xef\x76\x20\x9b\xf7\x37\x69\x86\x36\xf4\xa7\xd1\x83\x06\x56\xc8\x93\x70\xf8\xc2\xc8\x17\x60\x14\xc3\xe8\x5f\xe3\xa2\x86\xe3\x69\x5d\xb2\x11\xb4\xba\xfb\x58\xb1\xfc\x60\x65\x7f\x97\x72\x05\x4f\xa1\x60\x85\xcf\x3d\xd3\xcd\x35\x24\x86\x36\x76\x85\x51\x0a\x05\x55\x30\xe5\x9a\xab\x0d\x49\x31\xcc\x4c\x8d\xa9\x65\xe5\x3a\xf4\xf0\x6f\xf4\x89\x1d\x77\xde\x53\x35\x9e\xff\x60\x33\x31\x0d\xe2\x99\x59\x5e\x06\x5f\x1d\x57\xc2\xa4\xa9\xd1\x03\x71\x9c\x4e\x63\x2f\x11\xd9\x4b\x54\xf6\xff\x90\x99\xbf\x39\xfe\xd2\x5d\x3c\x49\xa4\x6f\x44\xae\x98\x3f\xe4\xd0\x11\x2b\x60\xed\x18\x99\x00\x82\x03\xb2\x8b\x4b\x3a\xa2\x0d\xbc\xaa\xae\x1e\x40\x61\xde\x2f\x5b\xa2\xb3\xc5\x23\x27\x70\x68\x29\xee\x52\xed\x18\x9e\xc7\xd5\xbc\x12\x6a\x14\xa6\xa0\x23\x4a\x99\x3c\x2a\xcc\xac\x49\x72\x71\x30\x41\xb5\x94\x32\xd5\x3f\x85\xef\x29\x15\xf3\xaf\x4c\x86\x35\x12\x5c\xa3\x32\x19\x5a\x4c\xb9\x54\xc3\x7a\xa8\xd7\xd2\x1a\xed\xc7\x07\xdf\x51\x65\x85\x8b\x7b\x4f\x48\xa1\xd4\x58\xad\x86\x83\xe0\xe0\x02\x55\x0c\x96\x65\x96\xcf\x9a\x3e\x1b\xba\x69\x05\x20\x15\x04\xc9\xea\x33\xee\x4d\x91\x11\xdf\x4b\x31\xcc\x6e\x7e\xf8\x70\x39\x9d\xb1\xf7\xd7\xf3\xb0\x9a\x68\xdf\x39\xe6\x31\xcf\xd8\x82\xa7\x52\x6d\x62\xf8\xf9\x82\xdd\x5c\xcf\xfe\x1d\xc4\xea\x33\x0b\x9c\xbc\x89\xe1\xf6\xe6\xa7\xeb\xf7\xec\xf6\xe6\xfb\x0f\xd7\x85\xc8\x0f\x76\xdc\x39\xb9\x0c\x5f\x58\x01\xa6\x8d\xe3\x63\x81\xfa\x9e\x48\x32\x23\xf7\x86\xab\xb1\x77\x78\xb0\x5a\x1c\xb5\xc5\x62\x1b\x97\x9d\x27\x8a\xea\xd7\xff\x3a\x72\xb8\x0d\x46\x03\x19\xef\x5e\x9c\xdb\x2f\x28\x17\x17\x45\xfb\x37\xe4\x50\x38\xac\x1c\xed\x73\x61\x57\xc7\x45\xa4\x2a\x84\xf6\x53\xe0\x2f\x23\xbf\x5e\xfb\x9e\xfe\x7e\xca\x1c\x59\xe4\xe9\x9d\x72\x97\x45\x1b\xd6\x1e\x9c\x96\xc7\x3e\x7d\x08\x9d\xd5\x54\x1a\xd8\x05\x9a\xdb\x45\x05\xca\x97\xd8\xa7\x1f\x80\xfe\x74\x78\xc3\x32\x6b\xc8\x08\xa3\x98\xc9\x28\x9c\xbd\x7e\x38\x3e\x19\x65\x2f\xf3\xde\x57\x81\xb4\x69\xc2\x33\x42\x7b\x0a\xc4\xbe\x9d\x94\xf7\xa9\xf2\x7c\x52\x9f\x3b\x38\x59\x21\x57\xb4\xda\xb0\x8c\x6b\x29\x18\xad\x2c\xba\x95\x51\x49\x13\x41\x6d\x28\x2a\x0c\x15\x1b\x98\x58\xa1\x78\xdc\xcb\x42\xdf\x24\x2c\x35\xa1\x5d\x73\xd5\xba\x1b\x56\x8b\xec\x41\x52\xb8\x6a\xee\x6d\xd0\x86\x91\xe5\x8b\x85\x14\xac\x77\x6f\xae\xab\x70\x9b\x40\xe1\x75\x2d\xee\x11\x36\xe7\x6b\x38\x57\xf7\x83\xaf\xa1\x71\x40\x74\x93\xe8\x4d\xe9\xb4\x7a\x6b\xb8\x9b\xcd\xa3\xf7\xd2\x96\x84\xf3\x2a\xc0\x58\xe4\x8e\x4c\x0a\xf3\xf9\x0c\x9a\x77\x3d\x20\xd3\x79\x07\xe9\xef\x70\xf8\x83\xb4\x78\x09\x1b\x52\xae\xba\xc8\xec\x63\x33\x2c\xa3\x25\xb9\xf0\xa7\x21\xba\xd6\xe3\xd7\x18\xf6\x44\xc5\x93\x6d\xc1\xe3\xb3\x79\x74\x69\xa9\x73\x59\xcf\xac\x5c\x7b\xbd\x47\xdc\xd4\x5a\xcd\x95\xbe\x79\xb7\x78\x81\x54\xae\xee\x3f\xce\xa1\x7a\xff\xe8\x10\xca\xc1\x63\xc6\x57\x75\xc2\x0d\xbf\xb8\x7c\x15\x9c\xd3\x7a\xa1\x3a\xce\x39\xa3\xee\x23\xd5\xe8\x6c\xf0\xcd\xee\x0f\x7f\xf4\x75\xf2\x52\x03\xf5\xbf\x01\x00\x00\xff\xff\xbf\x46\xa5\xad\x97\x19\x00\x00"

func envoy116EnvoyConfigYamlBytes() ([]byte, error) {
	return bindataRead(
		_envoy116EnvoyConfigYaml,
		"envoy-1.16/envoy-config.yaml",
	)
}

func envoy116EnvoyConfigYaml() (*asset, error) {
	bytes, err := envoy116EnvoyConfigYamlBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "envoy-1.16/envoy-config.yaml", size: 6551, mode: os.FileMode(420), modTime: time.Unix(1612554066, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio17ApigeeEnvoyAdapterYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xbc\x56\xcd\x6e\xe3\x36\x10\xbe\xfb\x29\x88\xdc\xe9\x9f\xb6\x7b\x58\x01\x7b\x08\xb6\x8b\x34\x40\x9d\x35\x9a\xb4\x77\x86\x1a\xcb\x44\x29\x0e\x3b\x1c\xa9\x55\x0d\xbf\x7b\x41\x51\x92\xa5\x24\xaa\xdd\x60\x51\x5f\x6c\xcf\xef\xc7\x99\x6f\xc8\x51\xde\xfc\x06\x14\x0c\xba\x4c\x28\xef\xc3\xaa\xde\x2c\x7e\x37\x2e\xcf\xc4\x8f\xe0\x2d\x36\x25\x38\x5e\x94\xc0\x2a\x57\xac\xb2\x85\x10\x4e\x95\x10\x4d\x4d\x01\x20\x09\x4a\x64\x90\x01\xa8\x36\x1a\x24\xb8\x1a\x9b\xce\x26\x78\xa5\x21\x13\xc7\xe3\xf2\xa1\xff\x77\x3a\x2d\x82\x07\x1d\xa3\x10\x78\x6b\xb4\x0a\x99\xd8\x2c\x84\x08\x60\x41\x33\x52\xd4\x08\x51\x2a\xd6\x87\x9f\xd5\x33\xd8\x90\x04\x22\x22\xbb\x94\x93\xa1\xf4\x56\x31\x74\x31\x46\x88\xdb\x00\xce\x21\x2b\x36\xe8\x86\x98\x42\x04\x93\x83\x56\xb4\x34\x81\x0d\x2e\x0d\xae\x08\xfe\x24\xc3\x70\xeb\xfd\x4f\x4f\x4f\xbb\x1d\xe1\x33\x50\xc8\xc4\x0d\x53\x05\x37\x83\x9b\x27\x2c\x81\x0f\x50\x85\xe8\xe3\x15\x1f\x32\xb1\x2a\x81\xc9\xe8\x30\x67\x84\xc4\x99\xb8\xf9\xb0\x5e\x6f\xe6\xe2\x04\x7d\x80\x58\xd9\x03\xb3\x9f\x0b\x13\x34\x29\x0f\x17\x00\x71\x13\x4d\xce\xb2\x58\xf2\xce\xd4\x4e\x8a\x7a\x55\x59\xd3\xa7\xee\x29\x52\x6f\x06\x19\x52\xd1\xb6\xf7\x2b\x15\xa7\xd3\x20\x05\x57\xb7\xd2\x2f\xae\xee\xa4\x7d\xcb\xdb\xdf\x29\xfa\xad\xd6\x58\x39\x7e\xb8\x82\x4a\xc9\x4b\x57\x64\xb8\xf9\x8c\x8e\xe1\x2f\xce\x84\x18\xd2\x51\xe5\x6e\xc3\xaf\x01\x28\x13\x1f\x3f\x7e\x9c\x8a\xef\x08\x2b\xff\x86\xfc\x01\xdd\x2f\x88\x9c\x89\x58\xc5\x4e\xa5\xd1\xb1\x32\x2e\xb6\xbb\x93\xc8\xab\x98\x9e\x3e\xa6\x54\x45\x6c\x4b\x81\x58\x58\x58\x75\x2e\xad\x8d\x54\xb9\xf2\x0c\x94\x1d\x8f\xcb\xfb\x68\xf6\xa4\x8a\xd3\xe9\x66\xea\xba\xab\xac\xdd\xa1\x35\xba\xc9\xc4\xfd\xfe\x01\x79\x47\x10\xe2\xe0\x0d\x1d\x46\xe2\x51\xdf\xe4\x19\xef\xae\x65\xd6\x87\xf5\x7a\x3d\x68\xad\xa9\xc1\x41\x08\x2d\x7f\xcf\x4e\xa2\xa5\xd6\x1d\xf0\x58\x24\x44\xc7\xdf\x03\x28\xcb\x87\xbf\xa7\xaa\x3e\xf6\x66\x24\xde\x2b\x63\x2b\x82\xa7\x03\x41\x38\xa0\xcd\xd3\x04\x0f\x2e\x40\x06\xf3\x47\xd0\xe8\xf2\x38\xdc\x67\x54\x04\x2a\x37\xff\x27\xac\xef\xd7\x57\xe1\x52\x54\x84\x71\x6a\x29\xa4\xb4\x58\x48\x0b\x35\xd8\x4f\x39\x3c\x57\xc5\x0b\xad\x46\xb7\x37\xc5\xa7\x55\xfa\xee\xbe\x96\x8d\x2a\xed\xe8\xb0\x01\x2b\xd2\x30\x89\x6c\x4d\x69\x38\x4c\x8f\xa9\x7d\x15\xd1\xac\xcb\x89\xb4\x84\x12\xa9\x69\x15\x5b\x33\xd2\x10\xfc\x51\x41\x98\x89\x71\x4d\x88\x1a\x6d\x55\xc2\x36\x0e\xdf\x84\x4e\x65\x94\xec\x52\xc9\xd3\x79\x46\xc1\xae\x9f\x83\xd4\xe5\xaf\xce\x36\xdd\x70\x1d\x8f\x52\x98\xbd\x58\xde\x87\xbb\xcf\xbb\xad\x72\xaa\x80\xbc\xbd\x16\x7a\xc5\xad\x53\xb6\x61\xa3\xc3\x23\x68\x02\x1e\x5d\x24\x53\x50\xaa\xb7\x93\xa1\x35\x7c\x0d\x6f\xde\xe0\x05\xa6\x94\x1c\x6c\x80\x16\xc1\x17\xa7\x31\x87\x3c\xde\x45\xb3\xd9\xd1\x73\x37\xd4\x2b\xb6\xe1\x55\x6e\xb6\x41\xa6\xca\x5e\xcc\xea\xf2\xd9\x24\xbe\xbd\x00\xe6\xce\x37\xa7\x7d\xa3\xe0\xe3\x24\x09\xd6\xbb\x2e\xb5\xc4\x83\xad\xf2\xd9\x7f\xe2\xc2\xbb\x5b\x2e\x2f\x75\x32\xfd\x1d\xa3\xc9\x61\xaf\x2a\xcb\x5b\xcc\x21\x13\x3f\x7c\x37\x1e\xf8\x64\x9c\x5e\x98\xfe\x91\x92\xfd\xbb\x24\xdf\xc8\x71\x91\x14\x72\xbe\xdb\xef\x46\xd6\x15\xb2\xca\xb5\x4a\xe0\x46\x69\x65\xa2\xda\xcb\x8e\xca\x7f\x25\xc4\x37\xac\xd1\x34\xc1\x19\x86\x94\x72\x31\xde\x1a\x87\x85\xf1\x31\xf1\xe0\x1b\x6e\x8b\xd3\x8d\xe5\xaa\x6d\xe5\xf5\x56\x32\xdd\x48\xfa\x6d\x64\x78\x51\xe5\xf9\x3d\x49\xb5\x49\x90\x0b\xf2\xfa\xd5\x66\x7a\x09\xc1\x3f\x01\x00\x00\xff\xff\xce\xaa\x4c\x92\x4d\x0b\x00\x00"

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

	info := bindataFileInfo{name: "istio-1.7/apigee-envoy-adapter.yaml", size: 2893, mode: os.FileMode(420), modTime: time.Unix(1612554066, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio17EnvoyfilterSidecarYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xdc\x56\xdf\x6f\xdb\x36\x10\x7e\xd7\x5f\x71\xb0\x1f\x37\xab\x09\x82\x61\x80\x9e\xe6\xa4\x4e\x6b\x2c\x4d\x0a\xc7\x6d\xf7\xa6\x30\xd4\x59\xbe\x85\x22\x39\xf2\xe4\x58\x0d\xf2\xbf\x0f\xfa\x95\x58\x8a\xe5\x25\x18\x86\x01\xf5\x83\x21\xf0\xbe\xbb\xfb\xee\xf8\x1d\xc9\x31\xcc\xb5\x67\xa1\x94\x07\xa1\x61\xee\x99\x0c\xcc\xf4\xc6\x14\xe7\xa4\x18\x1d\x90\x06\x5e\x23\x24\xb8\x12\xb9\x62\xd0\x22\x43\x6f\x85\xc4\x30\x18\xc3\x9c\x41\x58\xab\x08\x3d\xb0\x01\xa1\x14\x78\x74\x1b\x92\xe8\x5b\xb7\x67\x38\xcc\x57\x50\x98\x1c\xee\xc9\xaf\x7f\x2e\xbf\x82\x31\x64\xa2\x00\x16\xa4\x8c\x83\xdb\x02\xbc\x45\x49\xab\x82\x74\x0a\x37\xf7\xc6\xdd\x29\x23\x92\x6b\x54\x28\xd9\xb8\x1b\x58\x19\xd7\x20\x48\x02\x0b\x97\x22\xfb\x92\xc3\x17\x8f\x1e\x6e\x84\xa5\x14\x71\xe2\x30\x33\x8c\x93\x86\xc5\x04\xcb\x3a\xc2\xda\x16\xfd\x72\x74\x74\x74\x03\xc2\x37\xce\x61\x10\x8c\x61\xb9\x26\x0f\xe4\xab\xe0\x75\xe9\xc7\xe1\xaf\x3f\x85\x41\x20\x2c\x7d\x45\xe7\xc9\xe8\x08\x34\x72\x49\x87\x74\x1a\x52\x89\x09\xc9\xbc\xdb\x1c\x0b\x65\xd7\xe2\x24\xb8\x23\x9d\x44\xbb\x0d\x0b\x32\x64\x91\x08\x16\x51\x00\x55\xf9\x11\x74\xc9\x3d\x3c\x84\xcb\x8a\xc1\x75\xcd\x32\xbc\x14\x19\x3e\x3e\x36\xe8\xaa\x59\x51\xdb\xee\xa0\xac\xb8\x0c\xd4\xef\x47\xb9\x06\xa0\xc4\x2d\x2a\x5f\x7f\x03\x64\x42\x8b\x14\x93\xc9\x6d\xd1\xa6\x0c\x00\xa4\xd1\x2b\x4a\x3f\x0b\x96\x6b\xf4\x51\x10\x00\x4c\xaa\x3d\x2b\x96\x26\x82\x8f\xcb\xe5\xe7\xf8\x7c\x7e\xb1\x9c\x2d\x82\x3a\x02\xcb\x75\x1b\x4e\x1a\xcd\xb8\xe5\x08\xae\xe7\xef\x67\x67\xd3\x45\x3c\xbf\x3c\xbd\xfa\x72\xf9\xbe\x31\x2b\xf2\x8c\x1a\x5d\x0b\x07\x58\x55\xf5\x9f\xad\x05\xe9\xe7\xc5\x76\x79\x77\xa5\xed\x4b\xbd\x3d\x6b\x66\x1b\x4b\xa3\x35\x4a\x26\xa3\xe3\xba\x0c\xd7\xc1\xfb\xfc\xf6\x7c\x4f\x98\x6e\x20\x67\x72\x6e\xfc\xaa\x3f\xbb\x5b\x8d\xb1\xe8\x04\x57\xfb\x39\xbf\xbc\x9e\x2d\x96\xf1\xe9\xec\xfc\x6a\x31\x6b\xcc\x1b\xa1\x72\x7c\x0e\xbe\x1b\xb6\xe6\xef\x2b\x9e\x21\x6e\x39\x16\x39\xaf\xbf\x3f\x41\xb9\xb0\x98\xc4\x75\x9b\x77\xd9\x8d\x7e\x2b\x2d\xa3\xa8\x02\x84\xa9\x31\xa9\x42\x61\xc9\x87\xd2\x64\xef\xea\xc8\xb8\x65\xd4\xa5\xc6\xfc\x40\x92\x70\x73\x12\xce\xb6\x3c\xed\x24\x04\x60\x27\xb4\xb7\xc6\x71\x2c\x2c\xc5\x9b\x56\xa7\x5f\x4f\x76\x30\xa9\xb3\x32\x6e\xe6\xa0\xdb\xb4\x9a\x4a\x5c\x02\xfa\xdd\xac\x27\x23\xce\x1d\xf5\x45\x3b\x38\x51\xbd\x08\x9e\x05\xc7\xd6\xe1\x8a\xb6\x03\x21\x3a\x0e\x4c\x19\x9a\x9c\x23\x38\xf6\x3b\xeb\xed\x04\xc5\x8d\x04\xe3\xa7\xc1\xf0\x5d\xc6\x93\x7d\x5b\xf4\xe7\x7d\xdd\x3d\xfd\x43\x8b\x7d\x50\x95\xaf\x91\xfe\xf4\xbc\x6d\xc2\xeb\x95\xef\x6e\x85\xfc\x2f\x45\x5f\xc6\x2f\xf5\xbe\x38\x9d\x9e\xed\x44\x74\xb9\xea\xef\xba\x90\x75\x31\xd3\x8b\x8b\xab\x6f\x1d\x8b\x35\x8a\x24\xf5\xf1\xd0\x0a\xb1\xe9\xbb\x79\xd1\x58\x00\xeb\x48\x4b\xb2\x42\xbd\xf0\xad\x34\xa4\x8b\x08\xd8\xe5\xf8\xd2\x0f\x5d\x46\xbe\x2a\x67\x9f\xe3\x1a\x45\x82\x2e\x82\x07\x18\x95\x8d\x1d\x45\x30\xfa\x63\x32\xad\xd9\x94\x53\x6d\x1c\x7d\xc7\x64\x04\x8f\x3d\xad\x5e\xce\x96\xdf\xae\x16\xbf\xff\x8f\x72\x1d\x1d\xd4\xeb\xe8\xa0\xca\x3e\xcd\x16\x1f\x06\x0e\xd6\x7f\x14\xce\xe8\x4d\xca\x69\xae\xe6\x21\x9a\xa5\x9e\x3e\x32\xdb\xb3\x27\xcb\xa7\x5d\xfe\xad\x9c\x24\x7a\x1f\x2b\xd3\x21\x34\xe9\x4c\xc2\x33\x26\x6d\x05\x5b\x1d\xa0\xdd\xc3\x6c\xa0\x36\x78\xf3\x60\xf4\xd2\x95\x99\xda\x52\x3e\x38\x2b\xa7\x95\xf9\xc2\xa4\x67\x55\xae\x5e\x2a\x69\xb2\xcc\xe8\x01\x1e\xaf\xbb\x3c\x1a\x15\x99\x34\xde\xf7\x80\xd9\x77\x90\xc3\xc1\x2b\xa7\xb1\x0f\x5f\x3c\x0d\xb5\x7f\x7d\xfd\xd4\xbf\x37\x5e\x42\x00\x22\x49\xa8\x54\x87\x50\xb1\xc3\xbf\x72\xf4\x1c\xd7\x93\xeb\x63\x36\x7d\x65\x40\xa5\x8e\x48\xd4\xe3\xcb\x05\x8c\x9f\x1e\xc7\x75\x01\xcd\xd4\xf7\x5c\xc6\xed\xd0\x36\x66\xff\x22\xe4\x76\xd2\x70\xad\xb7\x9f\xcd\x1d\xea\x03\x20\x4b\x07\x8d\xd6\x99\x24\x97\x7c\x28\x4d\xf9\x74\x97\xd5\xcc\x0e\x83\xa4\x22\xd4\x4c\xc9\x30\x22\xc1\x0d\xaa\x72\xfa\x31\x13\xa4\x86\x71\xa8\x37\xe4\x8c\xce\x50\xf3\xdf\x01\x00\x00\xff\xff\x48\x10\x48\x7b\x74\x0c\x00\x00"

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

	info := bindataFileInfo{name: "istio-1.7/envoyfilter-sidecar.yaml", size: 3188, mode: os.FileMode(420), modTime: time.Unix(1612554066, 0)}
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

	info := bindataFileInfo{name: "istio-1.7/httpbin.yaml", size: 704, mode: os.FileMode(420), modTime: time.Unix(1612554066, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

var _istio17RequestAuthenticationYaml = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\x9c\x92\x4f\x6f\xdb\x38\x10\xc5\xef\xfa\x14\x0f\xd6\x6d\xb1\x92\x37\xd8\x1c\x16\xba\x65\x4f\xcd\x1f\x14\x46\xea\x36\x87\xa2\x07\x8a\x1a\x47\x53\x53\xa4\xc2\x19\xd9\x50\x05\x7d\xf7\x82\x76\x9c\x14\x81\x0b\x04\xd5\x89\x9c\x79\x7a\xef\x01\x3f\xe6\xf8\x18\x94\x2a\x5c\x79\x5c\x0d\xda\x86\xc8\x3f\x8c\x72\xf0\xab\xe0\xd8\x8e\x10\xd3\xf5\x8e\xc0\x02\x69\xc3\xde\xa3\x26\x17\xf6\x30\xbe\x81\x0d\x5d\x47\x5e\xa9\x41\x18\xb4\xcc\x72\xfc\x3f\xc2\x07\x45\x6b\x76\xec\x1f\x61\xce\xfa\xfd\x0d\x62\x6d\x29\xe2\x6a\x75\x8d\x5b\x1a\x05\x21\xe2\xe6\x61\x2d\xb0\x26\x99\x67\x39\x06\xa1\x06\xf5\x08\xeb\x98\xbc\x4a\x89\xeb\x0d\xc6\x30\x80\xbc\xa9\x1d\x41\x5b\x3a\x6f\x7c\xf3\xb0\x86\x86\x2d\x79\xc1\x9e\x9d\xcb\x72\xd4\x84\x48\x4f\x03\x47\x6a\x0e\x8d\x5f\x32\xd3\xfe\xd0\x75\x1f\xe2\x36\x65\x69\x4b\x9d\x90\xdb\x91\x94\x59\x66\x7a\xfe\x42\x51\x38\xf8\x0a\x42\x76\x88\xac\x63\xc9\xa2\x1c\x4a\x0e\xcb\xdd\x45\x4d\x6a\x2e\xb2\x2d\xfb\xa6\xc2\x3d\x3d\x0d\x24\x9a\x0a\x91\x57\xb6\x87\x46\x59\x47\x6a\x1a\xa3\xa6\xca\x00\x6f\x3a\xaa\x60\x7a\x7e\x24\x7a\xbe\x4a\x6f\x2c\x55\x68\x68\x63\x06\xa7\x99\xf4\x64\x93\x52\xc8\x91\xd5\x10\xd3\x19\xe8\x8c\xda\xf6\xce\xd4\xe4\xe4\x38\x48\x23\x6f\x1e\xa9\x29\xea\xf1\x17\xc3\xef\x7b\xbd\x1f\x1c\x1d\x44\x05\x58\x64\xa0\x58\x61\x9a\xca\x9b\x87\xf5\x2a\x86\x1d\x37\x14\x6f\x69\x9c\xe7\x0c\x98\xa6\x02\xbc\x41\x79\x3f\x78\xe5\x8e\xd6\x77\x9f\x0e\xe3\x64\xb2\x95\xcf\x91\x2b\xb4\xaa\xbd\x54\xcb\xe5\x34\x9d\x44\x1f\x82\xe8\x3c\x4f\x13\x6f\xe0\xe9\xe5\xd7\x55\x88\x8a\xc5\xe5\xe5\xbf\x8b\x79\xae\x5e\xc5\x69\x9c\xc4\xe4\x9b\x79\x5e\x46\xea\x82\x52\x71\x80\xb2\xb4\x14\x55\x9e\x3b\x90\x13\x3a\x97\xfc\xee\xe0\xff\xfe\xf9\xb3\xdc\xb4\xce\x72\x14\x45\x91\xe5\x78\x1f\xe7\x1c\x47\xd2\x67\xde\x5c\x96\xe3\x95\x74\x8e\x37\xac\x4f\x83\x37\xb4\x73\x1c\x79\xa7\xf5\x2b\xf1\xfc\x2d\xf1\xfc\x77\xc4\xd3\x22\x1e\x81\xa7\x63\x81\x4d\x0c\xdd\x49\x5f\x40\xc2\x10\x2d\x9d\xee\xe9\x8b\xc7\x27\xba\x8a\xec\x2d\xf7\xc6\x49\x85\xaf\x8b\xbf\x16\xdf\x7e\x06\x00\x00\xff\xff\xf7\x60\xc4\xa8\xf9\x03\x00\x00"

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

	info := bindataFileInfo{name: "istio-1.7/request-authentication.yaml", size: 1017, mode: os.FileMode(420), modTime: time.Unix(1612554066, 0)}
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
	"envoy-1.16/envoy-config.yaml":          envoy116EnvoyConfigYaml,
	"istio-1.7/apigee-envoy-adapter.yaml":   istio17ApigeeEnvoyAdapterYaml,
	"istio-1.7/envoyfilter-sidecar.yaml":    istio17EnvoyfilterSidecarYaml,
	"istio-1.7/httpbin.yaml":                istio17HttpbinYaml,
	"istio-1.7/request-authentication.yaml": istio17RequestAuthenticationYaml,
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
	"envoy-1.16": &bintree{nil, map[string]*bintree{
		"envoy-config.yaml": &bintree{envoy116EnvoyConfigYaml, map[string]*bintree{}},
	}},
	"istio-1.7": &bintree{nil, map[string]*bintree{
		"apigee-envoy-adapter.yaml":   &bintree{istio17ApigeeEnvoyAdapterYaml, map[string]*bintree{}},
		"envoyfilter-sidecar.yaml":    &bintree{istio17EnvoyfilterSidecarYaml, map[string]*bintree{}},
		"httpbin.yaml":                &bintree{istio17HttpbinYaml, map[string]*bintree{}},
		"request-authentication.yaml": &bintree{istio17RequestAuthenticationYaml, map[string]*bintree{}},
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
