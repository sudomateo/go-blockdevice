// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build unix && !linux

package blkid

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Probe returns the probe information for the specified file.
// Probing actual block devices is only supported on linux.
func Probe(f *os.File, opts ...ProbeOption) (*Info, error) {
	options := applyProbeOptions(opts...)

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat: %w", err)
	}

	info := &Info{}

	sysStat := st.Sys().(*syscall.Stat_t) //nolint:errcheck,forcetypeassert // we know it's a syscall.Stat_t

	switch sysStat.Mode & unix.S_IFMT {
	case unix.S_IFBLK:
		return nil, errors.New("probing block devices in only supported on linux")
	case unix.S_IFREG:
		// regular file (an image?), so use different settings
		info.Size = uint64(st.Size())
		info.SectorSize = options.SectorSize
		info.IOSize = info.SectorSize
	default:
		return nil, fmt.Errorf("unsupported file type: %s", st.Mode().Type())
	}

	if err := info.fillProbeResult(f, options); err != nil {
		return nil, fmt.Errorf("failed to probe: %w", err)
	}

	return info, nil
}
