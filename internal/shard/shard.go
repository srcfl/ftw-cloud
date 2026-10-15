// Package shard says which instance of the service holds a home.
// docs/protocol-cloud.md in srcfl/ftw, "Shards and restarts", is the rule.
//
// Every home lives on exactly one shard, and its box, phones, watch and
// extensions all meet there, so no home's data crosses between instances.
// Each instance holds the same directory: each shard's host, a shard for
// each of 256 buckets of homes, and single homes moved on their own. An
// instance that gets a home it does not hold names the host that does, and
// the client follows.
//
// With no directory file there is one shard, this one, and it holds every
// home.
package shard

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Buckets is how many buckets homes fall into. It never changes: moving
// homes moves buckets, or single homes, between shards.
const Buckets = 256

// bucketTag starts what a home's bucket is hashed from.
const bucketTag = "ftw.cloud.shard\x00"

// Bucket is the bucket a home falls into.
func Bucket(home string) int {
	sum := sha256.Sum256([]byte(bucketTag + home))
	return int(sum[0])
}

// Directory maps homes to shards.
type Directory struct {
	self    string
	hosts   map[string]string
	buckets [Buckets]string
	homes   map[string]string
}

// Single is the directory with one shard, named s1, at host.
func Single(host string) *Directory {
	d := &Directory{self: "s1", hosts: map[string]string{"s1": host}, homes: map[string]string{}}
	for i := range d.buckets {
		d.buckets[i] = "s1"
	}
	return d
}

// File is the directory as an operator writes it:
//
//	{
//	  "self": "s1",
//	  "shards": {"s1": "cloud.ftw.energy", "s2": "s2.cloud.ftw.energy"},
//	  "default": "s1",
//	  "buckets": {"s2": ["128-255"]},
//	  "homes": {"<home id>": "s2"}
//	}
//
// self is this instance. A bucket that no range names belongs to default.
// homes moves single homes and wins over buckets. Every instance carries the
// same file apart from self.
type File struct {
	Self    string              `json:"self"`
	Shards  map[string]string   `json:"shards"`
	Default string              `json:"default"`
	Buckets map[string][]string `json:"buckets"`
	Homes   map[string]string   `json:"homes"`
}

// Load reads a directory file. Every host must be the default shard's host
// or one label under it, as clients check before they follow.
func Load(path string) (*Directory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("shard: %s: %w", path, err)
	}
	d, err := f.Directory()
	if err != nil {
		return nil, fmt.Errorf("shard: %s: %w", path, err)
	}
	return d, nil
}

// Directory checks the file and builds the directory from it.
func (f File) Directory() (*Directory, error) {
	base, ok := f.Shards[f.Default]
	if !ok {
		return nil, fmt.Errorf("default shard %q has no host", f.Default)
	}
	for name, host := range f.Shards {
		if name == "" || !cloudwire.ShardHostOK(base, host) {
			return nil, fmt.Errorf("shard %q at %q: a host must be %s or one label under it", name, host, base)
		}
	}
	if _, ok := f.Shards[f.Self]; !ok {
		return nil, fmt.Errorf("self %q is not a shard", f.Self)
	}
	d := &Directory{self: f.Self, hosts: f.Shards, homes: map[string]string{}}
	for i := range d.buckets {
		d.buckets[i] = f.Default
	}
	set := map[int]string{}
	for name, ranges := range f.Buckets {
		if _, ok := f.Shards[name]; !ok {
			return nil, fmt.Errorf("buckets for %q, which is not a shard", name)
		}
		for _, r := range ranges {
			lo, hi, err := bucketRange(r)
			if err != nil {
				return nil, err
			}
			for b := lo; b <= hi; b++ {
				if other, ok := set[b]; ok && other != name {
					return nil, fmt.Errorf("bucket %d is both %q and %q", b, other, name)
				}
				set[b], d.buckets[b] = name, name
			}
		}
	}
	for home, name := range f.Homes {
		if !cloudwire.ValidHome(home) {
			return nil, fmt.Errorf("%q is not a home id", home)
		}
		if _, ok := f.Shards[name]; !ok {
			return nil, fmt.Errorf("home on %q, which is not a shard", name)
		}
		d.homes[home] = name
	}
	return d, nil
}

// bucketRange reads "7" or "128-255".
func bucketRange(r string) (int, int, error) {
	a, b, isRange := strings.Cut(r, "-")
	lo, err := strconv.Atoi(strings.TrimSpace(a))
	hi := lo
	if err == nil && isRange {
		hi, err = strconv.Atoi(strings.TrimSpace(b))
	}
	if err != nil || lo < 0 || hi >= Buckets || lo > hi {
		return 0, 0, fmt.Errorf("bucket range %q: want n or lo-hi within 0-%d", r, Buckets-1)
	}
	return lo, hi, nil
}

// Self is this instance's name.
func (d *Directory) Self() string { return d.self }

// Host is this instance's host.
func (d *Directory) Host() string { return d.hosts[d.self] }

// Shards is how many shards the directory names.
func (d *Directory) Shards() int { return len(d.hosts) }

// Owner is the host of the shard that holds home, and whether that is this
// instance.
func (d *Directory) Owner(home string) (host string, ours bool) {
	name, moved := d.homes[home]
	if !moved {
		name = d.buckets[Bucket(home)]
	}
	return d.hosts[name], name == d.self
}

// Ours reports whether this instance holds home.
func (d *Directory) Ours(home string) bool {
	_, ours := d.Owner(home)
	return ours
}
