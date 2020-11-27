// Copyright 2020 Coinbase, Inc.
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

package database

import (
	"github.com/coinbase/rosetta-sdk-go/storage/encoder"

	"github.com/dgraph-io/badger/v2"
)

// BadgerOption is used to overwrite default values in
// BadgerStorage construction. Any Option not provided
// falls back to the default value.
type BadgerOption func(b *BadgerStorage)

// WithCompressorEntries provides zstd dictionaries
// for given namespaces.
func WithCompressorEntries(entries []*encoder.CompressorEntry) BadgerOption {
	return func(b *BadgerStorage) {
		b.compress = true
		b.compressorEntries = entries
	}
}

// WithoutCompression disables zstd compression.
func WithoutCompression() BadgerOption {
	return func(b *BadgerStorage) {
		b.compress = false
	}
}

// WithIndexCacheSize override the DefaultIndexCacheSize
// setting for the BadgerDB. The size here is in bytes.
// If you provide custom BadgerDB settings, do not use this
// config as it will be overridden by your custom settings.
func WithIndexCacheSize(size int64) BadgerOption {
	return func(b *BadgerStorage) {
		b.badgerOptions.IndexCacheSize = size
	}
}

// WithCustomSettings allows for overriding all default BadgerDB
// options with custom settings.
func WithCustomSettings(settings badger.Options) BadgerOption {
	return func(b *BadgerStorage) {
		b.badgerOptions = settings
	}
}

// WithWriterShards overrides the default shards used
// in the writer utils.MutexMap. It is recommended
// to set this value to your write concurrency to prevent
// lock contention.
func WithWriterShards(shards int) BadgerOption {
	return func(b *BadgerStorage) {
		b.writerShards = shards
	}
}
