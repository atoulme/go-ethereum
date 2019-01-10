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

package canto

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// List of errors
var (
	ErrNoStakeToAccessSubnet    = errors.New("no stake to join subnet")
	ErrNoStakeToBecomeValidator = errors.New("no stake to become a validator")
	ErrInsufficientStake        = errors.New("not enough funds to stake the minimum amount")
	ErrSymAsym                  = errors.New("specify either a symmetric or an asymmetric key")
	ErrInvalidSymmetricKey      = errors.New("invalid symmetric key")
	ErrInvalidPublicKey         = errors.New("invalid public key")
	ErrInvalidSigningPubKey     = errors.New("invalid signing public key")
	ErrNoTopics                 = errors.New("missing topic(s)")
)

// PublicCantoAPI provides the canto RPC service that can be
// use publicly without security implications.
type PublicCantoAPI struct {
	c        *Canto
	mu       sync.Mutex
	lastUsed map[string]time.Time // keeps track when a filter was polled for the last time.
}

// NewPublicCantoAPI create a new RPC canto service.
func NewPublicCantoAPI(c *Canto) *PublicCantoAPI {
	api := &PublicCantoAPI{
		c:        c,
		lastUsed: make(map[string]time.Time),
	}
	return api
}

// Version returns the Canto sub-protocol version.
func (api *PublicCantoAPI) Version(ctx context.Context) string {
	println("looloolala")
	return ProtocolVersionStr
}

// Info contains diagnostic information.
type Info struct {
	AddressList []accounts.Account
}

// Info returns diagnostic information about the canto node.
func (api *PublicCantoAPI) Info(ctx context.Context) Info {
	keydir := "/Users/daniel/Library/Ethereum/keystore"
	accCache := keystore.NewKeyStore(keydir, keystore.StandardScryptN, keystore.StandardScryptP)
	println(keydir)
	return Info{
		AddressList: accCache.Accounts(),
	}
}

// Help returns all the methods available for the canto subprotocol
func (api *PublicCantoAPI) Help(ctx context.Context) []string {
	// just for convenience during development. Will be taken out or cleaned up later
	output := []string{"Version", "Info"}
	return output
}

// MarkTrustedPeer marks a peer trusted, which will allow it to send historic (expired) messages.
// Note: This function is not adding new nodes, the node needs to exists as a peer.
func (api *PublicCantoAPI) MarkTrustedPeer(ctx context.Context, url string) (bool, error) {
	n, err := enode.ParseV4(url)
	if err != nil {
		return false, err
	}
	return true, api.c.AllowP2PMessagesFromPeer(n.ID().Bytes())
}
