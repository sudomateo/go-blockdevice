// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package filesystem

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/siderolabs/go-retry/retry"

	"github.com/siderolabs/go-blockdevice/blockdevice/filesystem/ext4"
	"github.com/siderolabs/go-blockdevice/blockdevice/filesystem/iso9660"
	"github.com/siderolabs/go-blockdevice/blockdevice/filesystem/luks"
	"github.com/siderolabs/go-blockdevice/blockdevice/filesystem/msdos"
	"github.com/siderolabs/go-blockdevice/blockdevice/filesystem/vfat"
	"github.com/siderolabs/go-blockdevice/blockdevice/filesystem/xfs"
)

// SuperBlocker describes the requirements for file system super blocks.
type SuperBlocker interface {
	Is() bool
	Offset() int64
	Type() string
	Encrypted() bool
}

const (
	// Unknown filesystem.
	Unknown string = "unknown"
)

// Probe checks partition type.
func Probe(path string) (SuperBlocker, error) { //nolint:ireturn
	var (
		f   *os.File
		err error
	)

	// Sleep for up to 5s to wait for kernel to create the necessary device files.
	// If we dont sleep this becomes racy in that the device file does not exist
	// and it will fail to open.
	err = retry.Constant(5*time.Second, retry.WithUnits((50 * time.Millisecond))).Retry(func() error {
		if f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC, os.ModeDevice); err != nil {
			if os.IsNotExist(err) {
				return retry.ExpectedError(err)
			}

			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	//nolint: errcheck
	defer f.Close()

	superblocks := []SuperBlocker{
		&iso9660.SuperBlock{},
		&vfat.SuperBlock{},
		&msdos.SuperBlock{},
		&xfs.SuperBlock{},
		&luks.SuperBlock{},
		&ext4.SuperBlock{},
	}

	// This block must attempt to read each superblock and return only when a
	// valid superblock is found. This accounts for the case where there's an
	// error reading an earlier superblock but success reading a later superblock.
	// The errors encountered along the way are collected so users know which
	// superblocks were attempted to be read.
	for _, sb := range superblocks {
		if _, seekErr := f.Seek(sb.Offset(), io.SeekStart); seekErr != nil {
			err = errors.Join(err, seekErr)
			continue
		}

		if readErr := binary.Read(f, binary.BigEndian, sb); readErr != nil {
			err = errors.Join(err, readErr)
			continue
		}

		if sb.Is() {
			return sb, nil
		}
	}

	// No valid superblocks were found.
	if err != nil {
		return nil, err
	}

	return nil, nil //nolint:nilnil
}
