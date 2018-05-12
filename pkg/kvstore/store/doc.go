// Copyright 2018 Authors of Cilium
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

// Package store is a simple kvstore backed shared store where multiple
// collaborators share keys with each other. A shared store is list of keys
// maintained as JSON under a common kvstore prefix.
//
// The shared store is aware of two key types:
//
// * local-keys: Local keys are keys owned by the local store instance and
//   constantly synchronized to the kvstore with a controller. A local key
//   consists of the JSON representation of the corresponding go structure
//   and a key name to represent the key in the kvstore. It is the
//   responsibility of each collaborator to make key names unique across all
//   collaborators of a shared store.
//
// * shared-keys: Shared keys is the sum of all local keys by all
//   collaborators. The list of shared keys is maintained by listening to
//   kvstore events.
//
// Collaborators can join a shared store by subscribing to kvstore events of
// the kvstore prefix of the shared store.
package store
