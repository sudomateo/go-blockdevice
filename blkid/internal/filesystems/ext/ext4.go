// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package ext

import (
	"github.com/siderolabs/go-blockdevice/v2/blkid/internal/magic"
	"github.com/siderolabs/go-blockdevice/v2/blkid/internal/probe"
)

// Probe4 for ext4.
type Probe4 struct {
	probeCommon
}

// Name returns the name of the xfs filesystem.
func (p *Probe4) Name() string {
	return "ext4"
}

// Probe runs the further inspection and returns the result if successful.
func (p *Probe4) Probe(r probe.Reader, _ magic.Magic) (*probe.Result, error) {
	sb, err := p.readSuperblock(r)
	if err != nil || sb == nil {
		return nil, err
	}

	// distinguish from jbd
	if sb.Get_s_feature_incompat()&EXT3_FEATURE_INCOMPAT_JOURNAL_DEV != 0 {
		return nil, nil //nolint:nilnil
	}

	// ext4 has at least one feature which ext3 doesn't understand
	if (sb.Get_s_feature_ro_compat()&EXT3_FEATURE_RO_COMPAT_UNSUPPORTED) == 0 &&
		(sb.Get_s_feature_incompat()&EXT3_FEATURE_INCOMPAT_UNSUPPORTED) == 0 {
		return nil, nil //nolint:nilnil
	}

	return p.buildResult(sb)
}
