// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//go:build linux

package swap_test

import (
	"errors"
	randv2 "math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/freddierice/go-losetup/v2"
	"github.com/google/uuid"
	"github.com/siderolabs/go-pointer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/siderolabs/go-blockdevice/v2/blkid"
	"github.com/siderolabs/go-blockdevice/v2/swap"
)

func TestFormat(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root privileges")
	}

	tmpDir := t.TempDir()

	rawImage := filepath.Join(tmpDir, "image.raw")

	f, err := os.Create(rawImage)
	require.NoError(t, err)

	require.NoError(t, f.Truncate(100*1024*1024))
	require.NoError(t, f.Close())

	loDev := losetupAttachHelper(t, rawImage, false)

	t.Cleanup(func() {
		assert.NoError(t, loDev.Detach())
	})

	devPath := loDev.Path()

	t.Logf("formatting as swap: %s", devPath)

	swapUUID := uuid.New()
	swapLabel := "test-swap"

	err = swap.Format(devPath, swap.FormatOptions{
		UUID:  swapUUID,
		Label: swapLabel,
	})
	require.NoError(t, err)

	info, err := blkid.ProbePath(devPath)
	require.NoError(t, err)

	assert.Equal(t, "swap", info.Name)
	assert.Equal(t, swapUUID, pointer.SafeDeref(info.UUID))
	assert.Equal(t, swapLabel, pointer.SafeDeref(info.Label))
}

func TestOnOff(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root privileges")
	}

	if hostname, _ := os.Hostname(); hostname == "buildkitsandbox" { //nolint: errcheck
		t.Skip("test not supported under buildkit")
	}

	tmpDir := t.TempDir()

	rawImage := filepath.Join(tmpDir, "image.raw")

	f, err := os.Create(rawImage)
	require.NoError(t, err)

	require.NoError(t, f.Truncate(100*1024*1024))
	require.NoError(t, f.Close())

	loDev := losetupAttachHelper(t, rawImage, false)

	t.Cleanup(func() {
		assert.NoError(t, loDev.Detach())
	})

	devPath := loDev.Path()

	t.Logf("formatting as swap: %s", devPath)

	err = swap.Format(devPath, swap.FormatOptions{})
	require.NoError(t, err)

	t.Logf("enabling swap: %s", devPath)

	err = swap.On(devPath, swap.FLAG_DISCARD_ONCE)
	require.NoError(t, err)

	swaps, err := os.ReadFile("/proc/swaps")
	require.NoError(t, err)

	assert.Contains(t, string(swaps), devPath)

	t.Logf("disabling swap: %s", devPath)

	err = swap.Off(devPath)
	require.NoError(t, err)

	swaps, err = os.ReadFile("/proc/swaps")
	require.NoError(t, err)

	assert.NotContains(t, string(swaps), devPath)
}

func losetupAttachHelper(t *testing.T, rawImage string, readonly bool) losetup.Device { //nolint:unparam
	t.Helper()

	for range 10 {
		loDev, err := losetup.Attach(rawImage, 0, readonly)
		if err != nil {
			if errors.Is(err, unix.EBUSY) {
				spraySleep := max(randv2.ExpFloat64(), 2.0)

				t.Logf("retrying after %v seconds", spraySleep)

				time.Sleep(time.Duration(spraySleep * float64(time.Second)))

				continue
			}
		}

		require.NoError(t, err)

		return loDev
	}

	t.Fatal("failed to attach loop device") //nolint:revive

	panic("unreachable")
}
