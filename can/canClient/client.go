// Copyright 2017 The go-ethereum Authors
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

	canto "github.com/araskachoi/canto_go-ethereum/can/cantoV1"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/rpc"
)

// Client defines typed wrappers for the canto v1 RPC API.
type Client struct {
	c *rpc.Client
}

// Dial connects a client to the given URL.
func Dial(rawurl string) (*Client, error) {
	c, err := rpc.Dial(rawurl)
	if err != nil {
		return nil, err
	}
	return NewClient(c), nil
}

// NewClient creates a client that uses the given RPC client.
func NewClient(c *rpc.Client) *Client {
	return &Client{c}
}

// Version returns the canto sub-protocol version.
func (sc *Client) Version(ctx context.Context) (string, error) {
	var result string
	err := sc.c.CallContext(ctx, &result, "can_version")
	println("looloolala")
	return result, err
}

// Info returns diagnostic information about the canto node.
func (sc *Client) Info(ctx context.Context) (canto.NodeInfo, error) {
	var info canto.NodeInfo
	err := sc.c.CallContext(ctx, &info, "can_info")
	return info, err
}

func (sc *Client) Help(ctx context.Context) ([]string, error) {
	var output []string
	err := sc.c.CallContext(ctx, &output, "can_help")
	return output, err
}

func (sc *Client) Accounts(ctx context.Context) ([]accounts.Account, error) {
	var accounts []accounts.Account
	err := sc.c.CallContext(ctx, &accounts, "can_accounts")
	return accounts, err
}

// MarkTrustedPeer marks specific peer trusted, which will allow it to send historic (expired) messages.
// Note This function is not adding new nodes, the node needs to exists as a peer.
// func (sc *Client) MarkTrustedPeer(ctx context.Context, enode string) error {
// 	var ignored bool
// 	return sc.c.CallContext(ctx, &ignored, "can_markTrustedPeer", enode)
// }
