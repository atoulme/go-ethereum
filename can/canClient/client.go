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
	"math/big"

	"github.com/araskachoi/Canto/common"
	"github.com/araskachoi/Canto/common/hexutil"
	"github.com/araskachoi/Canto/core/types"
	"github.com/araskachoi/Canto/rlp"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	canto "github.com/ethereum/go-ethereum/can/cantoV1"
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
func (cc *Client) Version(ctx context.Context) (string, error) {
	var result string
	err := cc.c.CallContext(ctx, &result, "can_version")
	return result, err
}

// Info returns diagnostic information about the canto node.
func (cc *Client) Info(ctx context.Context) (canto.NodeInfo, error) {
	var info canto.NodeInfo
	err := cc.c.CallContext(ctx, &info, "can_info")
	return info, err
}

func (cc *Client) Help(ctx context.Context) ([]string, error) {
	var output []string
	err := cc.c.CallContext(ctx, &output, "can_help")
	return output, err
}

func (cc *Client) Accounts(ctx context.Context) ([]accounts.Account, error) {
	var accounts []accounts.Account
	err := cc.c.CallContext(ctx, &accounts, "can_accounts")
	return accounts, err
}

func (cc *Client) Stake(ctx context.Context) error {
	var output bool
	err := cc.c.CallContext(ctx, &output, "can_stake")
	return err
}

// CallContract executes a message call transaction, which is directly executed in the VM
// of the node, but never mined into the blockchain.
//
// blockNumber selects the block height at which the call runs. It can be nil, in which
// case the code is taken from the latest known block. Note that state from very old
// blocks might not be available.
func (cc *Client) CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	var hex hexutil.Bytes
	err := cc.c.CallContext(ctx, &hex, "can_call", toCallArg(msg), toBlockNumArg(blockNumber))
	if err != nil {
		return nil, err
	}
	return hex, nil
}

// SendTransaction injects a signed transaction into the pending pool for execution.
//
// If the transaction was a contract creation use the TransactionReceipt method to get the
// contract address after the transaction has been mined.
func (cc *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	data, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return err
	}
	return ec.c.CallContext(ctx, nil, "eth_sendRawTransaction", common.ToHex(data))
}

// MarkTrustedPeer marks specific peer trusted, which will allow it to send historic (expired) messages.
// Note This function is not adding new nodes, the node needs to exists as a peer.
// func (cc *Client) MarkTrustedPeer(ctx context.Context, enode string) error {
// 	var ignored bool
// 	return cc.c.CallContext(ctx, &ignored, "can_markTrustedPeer", enode)
// }
