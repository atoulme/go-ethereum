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
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/node"
	// "github.com/ethereum/go-ethereum/p2p/enode"
)

// List of errors
var (
	ErrNoStakeToAccessSubnet    = errors.New("no stake to join subnet")
	ErrNoStakeToBecomeValidator = errors.New("no stake to become a validator")
	ErrInsufficientStake        = errors.New("not enough funds to stake the minimum amount")
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
	fmt.Println("API VERSION")
	return ProtocolVersionStr
}

// Info contains diagnostic information.
type NodeInfo struct {
	AddressList     common.Address
	HasSubnetAccess bool
	IsValidator     bool
	subnetAddress   common.Address
}

// Account is a copy of the struct from account.go
// needed to override the type and expose the members to interact with
type Account struct {
	Address common.Address `json:"address"` // Ethereum account address derived from the key
	URL     accounts.URL   `json:"url"`     // Optional resource locator within a backend
}

// Info returns diagnostic information about the canto node.
func (api *PublicCantoAPI) Info(ctx context.Context) []interface{} {

	keydir := node.DefaultDataDir() + "/keystore"
	keyStore := keystore.NewKeyStore(keydir, keystore.StandardScryptN, keystore.StandardScryptP)
	Accounts := keyStore.Accounts()

	AccInfo := make([]interface{}, 0)
	for _, account := range Accounts {
		AccInfo = append(AccInfo, NodeInfo{
			AddressList: Account(account).Address,
		})
	}
	return AccInfo
}

// func (info *Info) CheckSubenetStatus() bool {

// }

// Help returns all the methods available for the canto subprotocol
// func (api *PublicCantoAPI) Help(ctx context.Context) []string {
// 	// just for convenience during development. Will be taken out or cleaned up later
// 	output := []string{"Version", "Info"}
// 	return output
// }

// MarkTrustedPeer marks a peer trusted, which will allow it to send historic (expired) messages.
// Note: This function is not adding new nodes, the node needs to exists as a peer.
// func (api *PublicCantoAPI) MarkTrustedPeer(ctx context.Context, url string) (bool, error) {
// 	n, err := enode.ParseV4(url)
// 	if err != nil {
// 		return false, err
// 	}
// 	return true, api.c.AllowP2PMessagesFromPeer(n.ID().Bytes())
// }
