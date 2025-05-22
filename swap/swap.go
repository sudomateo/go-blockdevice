// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

// Package swap provides functions to manage swap devices.
package swap

import (
	"fmt"
	"unsafe"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/siderolabs/go-blockdevice/v2/block"
	"github.com/siderolabs/go-blockdevice/v2/internal/swapstructs"
)

// Flags for swapon syscall.
//
//nolint:revive
const (
	FLAG_DISCARD       = 0x10000
	FLAG_DISCARD_ONCE  = 0x20000
	FLAG_DISCARD_PAGES = 0x40000
)

// On implements the swapon syscall to enable swap on a device.
func On(path string, flags uintptr) error {
	_p0, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}

	_, _, errno := unix.Syscall(unix.SYS_SWAPON, uintptr(unsafe.Pointer(_p0)), flags, 0)
	if errno != 0 {
		return errno
	}

	return nil
}

// Off implements the swapoff syscall to disable swap on a device.
func Off(path string) error {
	_p0, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}

	_, _, errno := unix.Syscall(unix.SYS_SWAPOFF, uintptr(unsafe.Pointer(_p0)), 0, 0)
	if errno != 0 {
		return errno
	}

	return nil
}

// FormatOptions contains options for formatting a swap device.
type FormatOptions struct {
	Label string
	UUID  uuid.UUID
}

const minGoodPages = 10

// Format implements the mkswap function to format a swap device.
func Format(path string, options FormatOptions) error {
	dev, err := block.NewFromPath(path, block.OpenForWrite())
	if err != nil {
		return err
	}

	defer dev.Close() //nolint:errcheck

	size, err := dev.GetSize()
	if err != nil {
		return fmt.Errorf("failed to get size: %w", err)
	}

	pageSize := unix.Getpagesize()

	if size < minGoodPages*uint64(pageSize) {
		return fmt.Errorf("swap size too small: %d", size)
	}

	if err = dev.FastWipe(); err != nil {
		return fmt.Errorf("failed to wipe device: %w", err)
	}

	header := make([]byte, pageSize)
	swapHeader := swapstructs.SwapHeader(header[swapstructs.SignatureOffset:])

	swapHeader.Put_version(1)
	swapHeader.Put_lastpage(uint32(size/uint64(pageSize) - 1))
	swapHeader.Put_nr_badpages(0)
	swapHeader.Put_uuid(options.UUID[:])

	volumeLabel := make([]byte, 16)
	copy(volumeLabel, options.Label)

	swapHeader.Put_volume(volumeLabel)

	signature := []byte("SWAPSPACE2")

	copy(header[len(header)-len(signature):], signature)

	if _, err = dev.File().WriteAt(header, 0); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}
