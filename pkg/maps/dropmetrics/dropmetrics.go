// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dropmetrics

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
)

var log = logging.DefaultLogger

const (
	MapName = "cilium_dropmetrics"
	// MaxEntries is the maximum number of keys that can be present in the
	// RemoteEndpointMap.
	MaxEntries = 65536
)

// Key implements the bpf.MapKey interface.
//
// Must be in sync with struct bpf_ipcache_key in <bpf/lib/eps.h>
type DropKey struct {
	Dropkey uint64
}

type DropValue struct {
	DropValueCount uint64
}

// NewValue returns a new empty instance of the structure representing the BPF
// map value
//func (k DropValue) NewValue() *DropValue { return &DropValue{} }
func NewValue(val uint64) *DropValue {
	result := DropValue{val}
	return &result
}
func NewKey(key uint64) DropKey {
	result := DropKey{key}
	return result
}

func (k DropKey) String() string {
	return fmt.Sprintf("%d", k.Dropkey)
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k DropKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(&k) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value
func (k DropKey) NewValue() bpf.MapValue { return &DropValue{} }

func (v *DropValue) String() string {
	return fmt.Sprintf("%d", v.DropValueCount)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *DropValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

var (
	// DropMetrics is a mapping of all endpoint IPs in the cluster which the corresponding
	// drops associated with this endpoint.
	DropMetrics = bpf.NewMap(
		MapName,
		bpf.BPF_MAP_TYPE_HASH,
		int(unsafe.Sizeof(DropKey{})),
		int(unsafe.Sizeof(DropValue{})),
		MaxEntries,
		0,
		func(key []byte, value []byte) (bpf.MapKey, bpf.MapValue, error) {
			k, v := DropKey{}, DropValue{}

			if err := bpf.ConvertKeyValue(key, value, &k, &v); err != nil {
				return nil, nil, err
			}
			return k, &v, nil
		})
)

func init() {
	err := bpf.OpenAfterMount(DropMetrics)
	if err != nil {
		log.WithError(err).Error("unable to open dropmetrics map")
	}
}
