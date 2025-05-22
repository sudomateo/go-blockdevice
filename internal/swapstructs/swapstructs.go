// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package swapstructs provides encoded definitions for swap on-disk structures.
package swapstructs

//go:generate go run ../cstruct/cstruct.go -pkg swapstructs -struct SwapHeader -input swap_header.h -endianness LittleEndian

// SignatureOffset is the offset of the signature in the swap header.
const SignatureOffset = 1024
