// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build unix

package blkid

import (
	"os"

	"golang.org/x/sys/unix"
)

// ProbePath returns the probe information for the specified path.
func ProbePath(devpath string, opts ...ProbeOption) (*Info, error) {
	f, err := os.OpenFile(devpath, os.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}

	defer f.Close() //nolint:errcheck

	return Probe(f, opts...)
}
