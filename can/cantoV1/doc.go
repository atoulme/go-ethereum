// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

/*
Package canto implements the Canto protocol (version 1).
*/

// Contains the Canto protocol constant definitions

package canto

import (
	"time"
)

// Canto protocol parameters
const (
	ProtocolVersion    = uint64(1) // Protocol version number
	ProtocolVersionStr = "1.0"     // The same, as a string
	ProtocolName       = "can"     // Nickname of the protocol in geth

	// canto protocol message codes, according to EIP-627
	statusCode           = 0   // used by canto protocol
	messagesCode         = 1   // normal canto message
	peerListUpdateExCode = 2   // peer list update
	p2pRequestCode       = 126 // peer-to-peer message, used by Dapp protocol
	p2pMessageCode       = 127 // peer-to-peer message (to be consumed by the peer, but not forwarded any further)
	NumberOfMessageCodes = 128

	SizeMask      = byte(3) // mask used to extract the size of payload size field from the flags
	signatureFlag = byte(4)

	// TopicLength     = 4  // in bytes
	signatureLength = 65 // in bytes
	aesKeyLength    = 32 // in bytes
	aesNonceLength  = 12 // in bytes; for more info please see cipher.gcmStandardNonceSize & aesgcm.NonceSize()
	keyIDSize       = 32 // in bytes
	// flagsLength     = 1

	EnvelopeHeaderLength = 20

	padSizeLimit      = 256 // just an arbitrary number, could be changed without breaking the protocol
	messageQueueLimit = 1024

	expirationCycle   = time.Second
	transmissionCycle = 300 * time.Millisecond

	DefaultTTL           = 50 // seconds
	DefaultSyncAllowance = 10 // seconds

	// canto protocol minmum values
	minStakeValue = 1 // in ETH
)
