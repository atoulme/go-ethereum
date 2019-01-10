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

	canto "github.com/araskachoi/canto_go-ethereum/can"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
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
	// println("looloolala")
	return result, err
}

// Info returns diagnostic information about the canto node.
func (sc *Client) Info(ctx context.Context) (canto.Info, error) {
	var info canto.Info
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
func (sc *Client) MarkTrustedPeer(ctx context.Context, enode string) error {
	var ignored bool
	return sc.c.CallContext(ctx, &ignored, "can_markTrustedPeer", enode)
}

// NewKeyPair generates a new public and private key pair for message decryption and encryption.
// It returns an identifier that can be used to refer to the key.
func (sc *Client) NewKeyPair(ctx context.Context) (string, error) {
	var id string
	return id, sc.c.CallContext(ctx, &id, "can_newKeyPair")
}

// AddPrivateKey stored the key pair, and returns its ID.
func (sc *Client) AddPrivateKey(ctx context.Context, key []byte) (string, error) {
	var id string
	return id, sc.c.CallContext(ctx, &id, "can_addPrivateKey", hexutil.Bytes(key))
}

// DeleteKeyPair delete the specifies key.
func (sc *Client) DeleteKeyPair(ctx context.Context, id string) (string, error) {
	var ignored bool
	return id, sc.c.CallContext(ctx, &ignored, "can_deleteKeyPair", id)
}

// HasKeyPair returns an indication if the node has a private key or
// key pair matching the given ID.
func (sc *Client) HasKeyPair(ctx context.Context, id string) (bool, error) {
	var has bool
	return has, sc.c.CallContext(ctx, &has, "can_hasKeyPair", id)
}

// PublicKey return the public key for a key ID.
func (sc *Client) PublicKey(ctx context.Context, id string) ([]byte, error) {
	var key hexutil.Bytes
	return []byte(key), sc.c.CallContext(ctx, &key, "can_getPublicKey", id)
}

// PrivateKey return the private key for a key ID.
func (sc *Client) PrivateKey(ctx context.Context, id string) ([]byte, error) {
	var key hexutil.Bytes
	return []byte(key), sc.c.CallContext(ctx, &key, "can_getPrivateKey", id)
}

// NewSymmetricKey generates a random symmetric key and returns its identifier.
// Can be used encrypting and decrypting messages where the key is known to both parties.
func (sc *Client) NewSymmetricKey(ctx context.Context) (string, error) {
	var id string
	return id, sc.c.CallContext(ctx, &id, "can_newSymKey")
}

// AddSymmetricKey stores the key, and returns its identifier.
func (sc *Client) AddSymmetricKey(ctx context.Context, key []byte) (string, error) {
	var id string
	return id, sc.c.CallContext(ctx, &id, "can_addSymKey", hexutil.Bytes(key))
}

// GenerateSymmetricKeyFromPassword generates the key from password, stores it, and returns its identifier.
func (sc *Client) GenerateSymmetricKeyFromPassword(ctx context.Context, passwd string) (string, error) {
	var id string
	return id, sc.c.CallContext(ctx, &id, "can_generateSymKeyFromPassword", passwd)
}

// HasSymmetricKey returns an indication if the key associated with the given id is stored in the node.
func (sc *Client) HasSymmetricKey(ctx context.Context, id string) (bool, error) {
	var found bool
	return found, sc.c.CallContext(ctx, &found, "can_hasSymKey", id)
}

// GetSymmetricKey returns the symmetric key associated with the given identifier.
func (sc *Client) GetSymmetricKey(ctx context.Context, id string) ([]byte, error) {
	var key hexutil.Bytes
	return []byte(key), sc.c.CallContext(ctx, &key, "can_getSymKey", id)
}

// DeleteSymmetricKey deletes the symmetric key associated with the given identifier.
func (sc *Client) DeleteSymmetricKey(ctx context.Context, id string) error {
	var ignored bool
	return sc.c.CallContext(ctx, &ignored, "can_deleteSymKey", id)
}

// Post a message onto the network.
// func (sc *Client) Post(ctx context.Context, message NewMessage) (string, error) {
// 	var hash string
// 	return hash, sc.c.CallContext(ctx, &hash, "can_post", message)
// }

// SubscribeMessages subscribes to messages that match the given criteria. This method
// is only supported on bi-directional connections such as websockets and IPC.
// NewMessageFilter uses polling and is supported over HTTP.
// func (sc *Client) SubscribeMessages(ctx context.Context, criteria Criteria, ch chan<- *Message) (ethereum.Subscription, error) {
// 	return sc.c.CanSubscribe(ctx, ch, "messages", criteria)
// }

// NewMessageFilter creates a filter within the node. This filter can be used to poll
// for new messages (see FilterMessages) that satisfy the given criteria. A filter can
// timeout when it was polled for in canto.filterTimeout.
// func (sc *Client) NewMessageFilter(ctx context.Context, criteria Criteria) (string, error) {
// 	var id string
// 	return id, sc.c.CallContext(ctx, &id, "can_newMessageFilter", criteria)
// }

// DeleteMessageFilter removes the filter associated with the given id.
// func (sc *Client) DeleteMessageFilter(ctx context.Context, id string) error {
// 	var ignored bool
// 	return sc.c.CallContext(ctx, &ignored, "can_deleteMessageFilter", id)
// }

// FilterMessages retrieves all messages that are received between the last call to
// this function and match the criteria that where given when the filter was created.
// func (sc *Client) FilterMessages(ctx context.Context, id string) ([]*Message, error) {
// 	var messages []*Message
// 	return messages, sc.c.CallContext(ctx, &messages, "can_getFilterMessages", id)
// }
