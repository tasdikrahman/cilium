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

package store

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

const (
	// listTimeoutDefault is the default timeout to wait for initial list
	// of objects from the kvstore
	listTimeoutDefault = 30 * time.Second

	// synchronizationIntervalDefault is the default interval to
	// synchronize keys with the kvstore
	synchronizationIntervalDefault = time.Minute

	// watcherChanSize is the size of the channel to buffer kvstore events
	watcherChanSize = 100
)

var (
	// controllers contains all controllers required for store management
	controllers controller.Manager

	log = logrus.WithField(logfields.LogSubsys, "shared-store")
)

// KeyCreator is a function to create a new empty Key instances.
type KeyCreator func() Key

// Configuration holds all configuration parameters of a shared store.
type Configuration struct {
	// Prefix is the key prefix shared by all keys
	Prefix string

	// SynchronizationInterval is the interval in which locally owned
	// values are synchronized with the kvstore
	SynchronizationInterval time.Duration

	// KeyCreator is called to allocate a Key instance when a new shared
	// key is discovered
	KeyCreator KeyCreator
}

// validate is invoked by JoinSharedStore to validate and complete the
// configuration. It returns nil when the configuration is valid.
func (c *Configuration) validate() error {
	if c.Prefix == "" {
		return fmt.Errorf("Prefix must be specified")
	}

	if c.KeyCreator == nil {
		return fmt.Errorf("KeyCreator must be specified")
	}

	if c.SynchronizationInterval == 0 {
		c.SynchronizationInterval = synchronizationIntervalDefault
	}

	return nil
}

// SharedStore is an instance of a shared store. It is created with
// JoinSharedStore() and released with the SharedStore.Close() function.
type SharedStore struct {
	// conf is a copy of the store configuration. These values are never
	// mutated after creation so it is safe to access this without a lock.
	conf Configuration

	// name is the name of the shared store. It is derived from the kvstore
	// prefix and must be unique.
	name string

	// controllerName is the name of the controller used to synchronize
	// with the kvstore. It is derived from the name.
	controllerName string

	// mutex protects mutations to localKeys and sharedKeys
	mutex lock.RWMutex

	// localKeys is a map of keys that are owned by the local instance. All
	// local keys are synchronized with the kvstore. This map can be
	// modified with UpdateLocalKey() and DeleteLocalKey().
	localKeys map[string]LocalKey

	// sharedKeys is a map of all keys that either have been discovered
	// from remote collaborators or successfully shared local keys. This
	// map represents the state in the kvstore and is updated based on
	// kvstore events.
	sharedKeys map[string]Key
}

// Key is the interface that a data structure must implement in order to be
// stored and shared via a SharedStore.
type Key interface {
	// GetKeyName must return the name of the key. The name of the key must
	// be unique within the store and stable for a particular key. The name
	// of the key must be identical across agent restarts as the keys
	// remain in the kvstore.
	GetKeyName() string

	// OnDelete is called when the key has been deleted from the shared store
	OnDelete()

	// OnUpdate is called whenever a change has occurred in the key
	OnUpdate()
}

// LocalKey is a Key which is owned by the local instance
type LocalKey Key

// JoinSharedStore creates a new shared store based on the provided
// configuration. An error is returned if the configuration is invalid. The
// store is initialized with the contents of the kvstore. An error is returned
// if the contents cannot be retrieved synchronously from the kvstore. Starts a
// controller to continuously synchronize the store with the kvstore.
func JoinSharedStore(c Configuration) (*SharedStore, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}

	s := &SharedStore{
		conf:       c,
		localKeys:  map[string]LocalKey{},
		sharedKeys: map[string]Key{},
	}

	s.name = "store-" + s.conf.Prefix
	s.controllerName = "kvstore-sync-" + s.name

	if err := s.listAndStartWatcher(); err != nil {
		return nil, err
	}

	controllers.UpdateController(s.controllerName,
		controller.ControllerParams{
			DoFunc: func() error {
				return s.syncLocalKeys()
			},
			RunInterval: s.conf.SynchronizationInterval,
		},
	)

	return s, nil
}

// Close stops participation with a shared store. This stops the controller
// started by JoinSharedStore().
func (s *SharedStore) Close() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	controllers.RemoveController(s.controllerName)

	for _, key := range s.localKeys {
		s.deleteLocalKey(key)
	}
}

// keyPath returns the absolute kvstore path of a key
func (s *SharedStore) keyPath(key Key) string {
	// WARNING - STABLE API
	return path.Join(s.conf.Prefix, key.GetKeyName())
}

// syncLocalKey synchronizes a key to the kvstore
func (s *SharedStore) syncLocalKey(key LocalKey) error {
	jsonValue, err := json.Marshal(key)
	if err != nil {
		return err
	}

	// Update key in kvstore, overwrite an eventual existing key, attach
	// lease to expire entry when agent dies and never comes back up.
	if err := kvstore.Update(s.keyPath(key), jsonValue, true); err != nil {
		return err
	}

	return nil
}

// syncLocalKeys synchronizes all local keys with the kvstore
func (s *SharedStore) syncLocalKeys() error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, key := range s.localKeys {
		if err := s.syncLocalKey(key); err != nil {
			return err
		}
	}

	return nil
}

// UpdateLocalKey adds a key to be synchronized with the kvstore
func (s *SharedStore) UpdateLocalKey(key LocalKey) {
	s.mutex.Lock()
	s.localKeys[key.GetKeyName()] = key
	s.mutex.Unlock()

	key.OnDelete()
}

// UpdateLocalKeySync synchronously synchronizes a local key with the kvstore
// and adds it to the list of local keys to be synchronized if the initial
// synchronous synchronization was successful
func (s *SharedStore) UpdateLocalKeySync(key LocalKey) error {
	s.UpdateLocalKey(key)

	if err := s.syncLocalKey(key); err != nil {
		s.DeleteLocalKey(key)
		return err
	}

	return nil
}

// deleteLocalKey must be called with s.mutex held
func (s *SharedStore) deleteLocalKey(key LocalKey) {
	err := kvstore.Delete(s.keyPath(key))

	name := key.GetKeyName()
	if _, ok := s.localKeys[name]; ok {
		delete(s.localKeys, name)
		key.OnDelete()

		if err != nil {
			s.getLogger().WithError(err).Warning("Unable to delete key in kvstore")
		}
	}
}

// DeleteLocalKey removes a key from bein synchronized with the kvstore
func (s *SharedStore) DeleteLocalKey(key LocalKey) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.deleteLocalKey(key)
}

// getLocalKeys returns all local keys
func (s *SharedStore) getLocalKeys() []Key {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	keys := make([]Key, len(s.localKeys))
	idx := 0
	for _, key := range s.localKeys {
		keys[idx] = key
		idx++
	}

	return keys
}

// getSharedKeys returns all shared keys
func (s *SharedStore) getSharedKeys() []Key {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	keys := make([]Key, len(s.sharedKeys))
	idx := 0
	for _, key := range s.sharedKeys {
		keys[idx] = key
		idx++
	}

	return keys
}

func (s *SharedStore) getLogger() *logrus.Entry {
	return log.WithFields(logrus.Fields{
		"storeName": s.name,
	})
}

func (s *SharedStore) updateKey(name string, value []byte) error {
	s.mutex.Lock()

	// shared key is seen for the first time
	if s.sharedKeys[name] == nil {
		if s.localKeys[name] != nil {
			// if local key, reuse key instance
			s.sharedKeys[name] = s.localKeys[name]
		} else {
			// allocate key for keys from collaborators
			s.sharedKeys[name] = s.conf.KeyCreator()
		}
	}

	err := json.Unmarshal(value, s.sharedKeys[name])
	s.mutex.Unlock()

	if err != nil {
		return err
	}

	s.sharedKeys[name].OnUpdate()
	return nil
}

func (s *SharedStore) deleteKey(name string) {
	s.mutex.Lock()
	existingKey := s.sharedKeys[name]
	delete(s.sharedKeys, name)
	s.mutex.Unlock()

	if existingKey == nil {
		s.getLogger().WithField("key", name).
			Warning("Unable to find deleted key in local state")
		return
	}

	existingKey.OnDelete()
}

func (s *SharedStore) listAndStartWatcher() error {
	listDone := make(chan bool)

	go s.watcher(listDone)

	select {
	case <-listDone:
	case <-time.After(listTimeoutDefault):
		return fmt.Errorf("Time out while retrieving initial list of objects from kvstore")
	}

	return nil
}

func (s *SharedStore) watcher(listDone chan bool) {
	watcher := kvstore.ListAndWatch(s.name+"-watcher", s.conf.Prefix, watcherChanSize)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			if event.Typ == kvstore.EventTypeListDone {
				s.getLogger().Debug("Initial list of objects received from kvstore")
				close(listDone)
				continue
			}

			logger := s.getLogger().WithFields(logrus.Fields{
				"key":       event.Key,
				"eventType": event.Typ,
			})

			logger.Infof("Received key update via kvstore [value %s]", event.Value)

			keyName := strings.TrimPrefix(event.Key, s.conf.Prefix)
			if keyName[0] == '/' {
				keyName = keyName[1:]
			}

			switch event.Typ {
			case kvstore.EventTypeCreate, kvstore.EventTypeModify:
				if err := s.updateKey(keyName, event.Value); err != nil {
					logger.WithError(err).Warningf("Unable to unmarshal store value: %s", event.Value)
				}

			case kvstore.EventTypeDelete:
				s.deleteKey(keyName)
			}
		}
	}
}
