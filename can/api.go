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
	return ProtocolVersionStr
}

// Info contains diagnostic information.
type Info struct {
	Memory      int `json:"memory"` // Memory size of the floating messages in bytes.
	AddressList map[string]string
}

// Info returns diagnostic information about the canto node.
func (api *PublicCantoAPI) Info(ctx context.Context) Info {
	stats := api.c.Stats()
	return Info{
		Memory:      stats.memoryUsed,
		AddressList: stats.addressList,
	}
}

// Help returns all the methods available for the canto subprotocol
func (api *PublicCantoAPI) Help(ctx context.Context) []string {
	// just for convenience during development. Will be taken out or cleaned up later
	output := []string{"Version", "Info", "MarkTrustedPeer"}
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

// NewKeyPair generates a new public and private key pair for message decryption and encryption.
// It returns an ID that can be used to refer to the keypair.
// func (api *PublicCantoAPI) NewKeyPair(ctx context.Context) (string, error) {
// 	return api.c.NewKeyPair()
// }

// AddPrivateKey imports the given private key.
// func (api *PublicCantoAPI) AddPrivateKey(ctx context.Context, privateKey hexutil.Bytes) (string, error) {
// 	key, err := crypto.ToECDSA(privateKey)
// 	if err != nil {
// 		return "", err
// 	}
// 	return api.c.AddKeyPair(key)
// }

// DeleteKeyPair removes the key with the given key if it exists.
// func (api *PublicCantoAPI) DeleteKeyPair(ctx context.Context, key string) (bool, error) {
// 	if ok := api.c.DeleteKeyPair(key); ok {
// 		return true, nil
// 	}
// 	return false, fmt.Errorf("key pair %s not found", key)
// }

// HasKeyPair returns an indication if the node has a key pair that is associated with the given id.
// func (api *PublicCantoAPI) HasKeyPair(ctx context.Context, id string) bool {
// 	return api.c.HasKeyPair(id)
// }

// GetPublicKey returns the public key associated with the given key. The key is the hex
// encoded representation of a key in the form specified in section 4.3.6 of ANSI X9.62.
// func (api *PublicCantoAPI) GetPublicKey(ctx context.Context, id string) (hexutil.Bytes, error) {
// 	key, err := api.c.GetPrivateKey(id)
// 	if err != nil {
// 		return hexutil.Bytes{}, err
// 	}
// 	return crypto.FromECDSAPub(&key.PublicKey), nil
// }

// GetPrivateKey returns the private key associated with the given key. The key is the hex
// encoded representation of a key in the form specified in section 4.3.6 of ANSI X9.62.
// func (api *PublicCantoAPI) GetPrivateKey(ctx context.Context, id string) (hexutil.Bytes, error) {
// 	key, err := api.c.GetPrivateKey(id)
// 	if err != nil {
// 		return hexutil.Bytes{}, err
// 	}
// 	return crypto.FromECDSA(key), nil
// }

// NewSymKey generate a random symmetric key.
// It returns an ID that can be used to refer to the key.
// Can be used encrypting and decrypting messages where the key is known to both parties.
// func (api *PublicCantoAPI) NewSymKey(ctx context.Context) (string, error) {
// 	return api.c.GenerateSymKey()
// }

// AddSymKey import a symmetric key.
// It returns an ID that can be used to refer to the key.
// Can be used encrypting and decrypting messages where the key is known to both parties.
// func (api *PublicCantoAPI) AddSymKey(ctx context.Context, key hexutil.Bytes) (string, error) {
// 	return api.c.AddSymKeyDirect([]byte(key))
// }

// GenerateSymKeyFromPassword derive a key from the given password, stores it, and returns its ID.
// func (api *PublicCantoAPI) GenerateSymKeyFromPassword(ctx context.Context, passwd string) (string, error) {
// 	return api.c.AddSymKeyFromPassword(passwd)
// }

// HasSymKey returns an indication if the node has a symmetric key associated with the given key.
// func (api *PublicCantoAPI) HasSymKey(ctx context.Context, id string) bool {
// 	return api.c.HasSymKey(id)
// }

// GetSymKey returns the symmetric key associated with the given id.
// func (api *PublicCantoAPI) GetSymKey(ctx context.Context, id string) (hexutil.Bytes, error) {
// 	return api.c.GetSymKey(id)
// }

// DeleteSymKey deletes the symmetric key that is associated with the given id.
// func (api *PublicCantoAPI) DeleteSymKey(ctx context.Context, id string) bool {
// 	return api.c.DeleteSymKey(id)
// }

// MakeLightClient turns the node into light client, which does not forward
// any incoming messages, and sends only messages originated in this node.
// func (api *PublicCantoAPI) MakeLightClient(ctx context.Context) bool {
// 	api.c.SetLightClientMode(true)
// 	return api.c.LightClientMode()
// }

// CancelLightClient cancels light client mode.
// func (api *PublicCantoAPI) CancelLightClient(ctx context.Context) bool {
// 	api.c.SetLightClientMode(false)
// 	return !api.c.LightClientMode()
// }

//go:generate gencodec -type NewMessage -field-override newMessageOverride -out gen_newmessage_json.go

// NewMessage represents a new canto message that is posted through the RPC.
// type NewMessage struct {
// 	SymKeyID  string `json:"symKeyID"`
// 	PublicKey []byte `json:"pubKey"`
// 	Sig       string `json:"sig"`
// 	TTL       uint32 `json:"ttl"`
// 	// Topic      TopicType `json:"topic"`
// 	Payload    []byte `json:"payload"`
// 	Padding    []byte `json:"padding"`
// 	TargetPeer string `json:"targetPeer"`
// }

// type newMessageOverride struct {
// 	PublicKey hexutil.Bytes
// 	Payload   hexutil.Bytes
// 	Padding   hexutil.Bytes
// }

// Post posts a message on the canto network.
// returns the hash of the message in case of success.
// func (api *PublicCantoAPI) Post(ctx context.Context, req NewMessage) (hexutil.Bytes, error) {
// 	var (
// 		symKeyGiven = len(req.SymKeyID) > 0
// 		pubKeyGiven = len(req.PublicKey) > 0
// 		err         error
// 	)

// user must specify either a symmetric or an asymmetric key
// if (symKeyGiven && pubKeyGiven) || (!symKeyGiven && !pubKeyGiven) {
// 	return nil, ErrSymAsym
// }

// params := &MessageParams{
// 	TTL:     req.TTL,
// 	Payload: req.Payload,
// 	Padding: req.Padding,
// 	// Topic:   req.Topic,
// }

// Set key that is used to sign the message
// if len(req.Sig) > 0 {
// 	if params.Src, err = api.c.GetPrivateKey(req.Sig); err != nil {
// 		return nil, err
// 	}
// }

// Set symmetric key that is used to encrypt the message
// if symKeyGiven {
// if params.Topic == (TopicType{}) { // topics are mandatory with symmetric encryption
// 	return nil, ErrNoTopics
// }
// if params.KeySym, err = api.c.GetSymKey(req.SymKeyID); err != nil {
// 	return nil, err
// }
// if !validateDataIntegrity(params.KeySym, aesKeyLength) {
// 	return nil, ErrInvalidSymmetricKey
// }
// }

// Set asymmetric key that is used to encrypt the message
// if pubKeyGiven {
// if params.Dst, err = crypto.UnmarshalPubkey(req.PublicKey); err != nil {
// 		return nil, ErrInvalidPublicKey
// 	}
// }

// encrypt and sent message
// cantoMsg, err := NewSentMessage(params)
// if err != nil {
// 	return nil, err
// }

// var result []byte

// env, err := cantoMsg.Wrap(params)
// if err != nil {
// 	return nil, err
// }

// send to specific node (skip PoW check)
// if len(req.TargetPeer) > 0 {
// 	n, err := enode.ParseV4(req.TargetPeer)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse target peer: %s", err)
// 	}
// err = api.c.SendP2PMessage(n.ID().Bytes(), env)
// if err == nil {
// 	hash := env.Hash()
// 	result = hash[:]
// }
// 	return result, err
// }

// err = api.c.Send(env)
// if err == nil {
// 	hash := env.Hash()
// 	result = hash[:]
// }
// return result, err
// }

//go:generate gencodec -type Criteria -field-override criteriaOverride -out gen_criteria_json.go

// Criteria holds various filter options for inbound messages.
// type Criteria struct {
// 	SymKeyID     string `json:"symKeyID"`
// 	PrivateKeyID string `json:"privateKeyID"`
// 	Sig          []byte `json:"sig"`
// 	// MinPow       float64     `json:"minPow"`
// 	// Topics   []TopicType `json:"topics"`
// 	AllowP2P bool `json:"allowP2P"`
// }

// type criteriaOverride struct {
// 	Sig hexutil.Bytes
// }

// Messages set up a subscription that fires events when messages arrive that match
// the given set of criteria.
// func (api *PublicCantoAPI) Messages(ctx context.Context, crit Criteria) (*rpc.Subscription, error) {
// 	var (
// 		symKeyGiven = len(crit.SymKeyID) > 0
// 		pubKeyGiven = len(crit.PrivateKeyID) > 0
// 		err         error
// 	)

// 	// ensure that the RPC connection supports subscriptions
// 	notifier, supported := rpc.NotifierFromContext(ctx)
// 	if !supported {
// 		return nil, rpc.ErrNotificationsUnsupported
// 	}

// 	// user must specify either a symmetric or an asymmetric key
// 	if (symKeyGiven && pubKeyGiven) || (!symKeyGiven && !pubKeyGiven) {
// 		return nil, ErrSymAsym
// 	}

// filter := Filter{
// PoW:      crit.MinPow,
// 	Messages: make(map[common.Hash]*ReceivedMessage),
// 	AllowP2P: crit.AllowP2P,
// }

// if len(crit.Sig) > 0 {
// 	if filter.Src, err = crypto.UnmarshalPubkey(crit.Sig); err != nil {
// 		return nil, ErrInvalidSigningPubKey
// 	}
// }

// for i, bt := range crit.Topics {
// 	if len(bt) == 0 || len(bt) > 4 {
// 		return nil, fmt.Errorf("subscribe: topic %d has wrong size: %d", i, len(bt))
// 	}
// 	filter.Topics = append(filter.Topics, bt[:])
// }

// listen for message that are encrypted with the given symmetric key
// if symKeyGiven {
// 	if len(filter.Topics) == 0 {
// 		return nil, ErrNoTopics
// 	}
// 	key, err := api.c.GetSymKey(crit.SymKeyID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if !validateDataIntegrity(key, aesKeyLength) {
// 		return nil, ErrInvalidSymmetricKey
// 	}
// 	filter.KeySym = key
// 	filter.SymKeyHash = crypto.Keccak256Hash(filter.KeySym)
// }

// listen for messages that are encrypted with the given public key
// if pubKeyGiven {
// 	filter.KeyAsym, err = api.c.GetPrivateKey(crit.PrivateKeyID)
// 	if err != nil || filter.KeyAsym == nil {
// 		return nil, ErrInvalidPublicKey
// 	}
// }

// id, err := api.c.Subscribe(&filter)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// create subscription and start waiting for message events
// 	rpcSub := notifier.CreateSubscription()
// 	go func() {
// 		// for now poll internally, refactor canto internal for channel support
// 		ticker := time.NewTicker(250 * time.Millisecond)
// 		defer ticker.Stop()

// 		for {
// 			select {
// 			case <-ticker.C:
// 				// if filter := api.c.GetFilter(id); filter != nil {
// 				// 	for _, rpcMessage := range toMessage(filter.Retrieve()) {
// 				// 		if err := notifier.Notify(rpcSub.ID, rpcMessage); err != nil {
// 				// 			log.Error("Failed to send notification", "err", err)
// 				// 		}
// 				// 	}
// 				// }
// 			case <-rpcSub.Err():
// 				// api.c.Unsubscribe(id)
// 				return
// 			case <-notifier.Closed():
// 				// api.c.Unsubscribe(id)
// 				return
// 			}
// 		}
// 	}()

// 	return rpcSub, nil
// }

//go:generate gencodec -type Message -field-override messageOverride -out gen_message_json.go

// Message is the RPC representation of a canto message.
// type Message struct {
// 	Sig       []byte `json:"sig,omitempty"`
// 	TTL       uint32 `json:"ttl"`
// 	Timestamp uint32 `json:"timestamp"`
// 	// Topic     TopicType `json:"topic"`
// 	Payload []byte `json:"payload"`
// 	Padding []byte `json:"padding"`
// 	// PoW       float64   `json:"pow"`
// 	Hash []byte `json:"hash"`
// 	Dst  []byte `json:"recipientPublicKey,omitempty"`
// }

// type messageOverride struct {
// 	Sig     hexutil.Bytes
// 	Payload hexutil.Bytes
// 	Padding hexutil.Bytes
// 	Hash    hexutil.Bytes
// 	Dst     hexutil.Bytes
// }

// ToCantoMessage converts an internal message into an API version.
// func ToCantoMessage(message *ReceivedMessage) *Message {
// 	msg := Message{
// 		Payload:   message.Payload,
// 		Padding:   message.Padding,
// 		Timestamp: message.Sent,
// 		TTL:       message.TTL,
// 		// PoW:       message.PoW,
// 		// Hash: message.EnvelopeHash.Bytes(),
// 		// Topic: message.Topic,
// 	}

// 	if message.Dst != nil {
// 		b := crypto.FromECDSAPub(message.Dst)
// 		if b != nil {
// 			msg.Dst = b
// 		}
// 	}

// 	if isMessageSigned(message.Raw[0]) {
// 		b := crypto.FromECDSAPub(message.SigToPubKey())
// 		if b != nil {
// 			msg.Sig = b
// 		}
// 	}

// 	return &msg
// }

// toMessage converts a set of messages to its RPC representation.
// func toMessage(messages []*ReceivedMessage) []*Message {
// 	msgs := make([]*Message, len(messages))
// 	for i, msg := range messages {
// 		msgs[i] = ToCantoMessage(msg)
// 	}
// 	return msgs
// }

// GetFilterMessages returns the messages that match the filter criteria and
// are received between the last poll and now.
// func (api *PublicCantoAPI) GetFilterMessages(id string) ([]*Message, error) {
// 	api.mu.Lock()
// 	f := api.c.GetFilter(id)
// 	if f == nil {
// 		api.mu.Unlock()
// 		return nil, fmt.Errorf("filter not found")
// 	}
// 	api.lastUsed[id] = time.Now()
// 	api.mu.Unlock()

// 	receivedMessages := f.Retrieve()
// 	messages := make([]*Message, 0, len(receivedMessages))
// 	for _, msg := range receivedMessages {
// 		messages = append(messages, ToCantoMessage(msg))
// 	}

// 	return messages, nil
// }

// DeleteMessageFilter deletes a filter.
// func (api *PublicCantoAPI) DeleteMessageFilter(id string) (bool, error) {
// 	api.mu.Lock()
// 	defer api.mu.Unlock()

// 	delete(api.lastUsed, id)
// 	return true, api.c.Unsubscribe(id)
// }

// NewMessageFilter creates a new filter that can be used to poll for
// (new) messages that satisfy the given criteria.
// func (api *PublicCantoAPI) NewMessageFilter(req Criteria) (string, error) {
// 	var (
// 		src     *ecdsa.PublicKey
// 		keySym  []byte
// 		keyAsym *ecdsa.PrivateKey
// 		topics  [][]byte

// 		symKeyGiven  = len(req.SymKeyID) > 0
// 		asymKeyGiven = len(req.PrivateKeyID) > 0

// 		err error
// 	)

// 	// user must specify either a symmetric or an asymmetric key
// 	if (symKeyGiven && asymKeyGiven) || (!symKeyGiven && !asymKeyGiven) {
// 		return "", ErrSymAsym
// 	}

// 	if len(req.Sig) > 0 {
// 		if src, err = crypto.UnmarshalPubkey(req.Sig); err != nil {
// 			return "", ErrInvalidSigningPubKey
// 		}
// 	}

// 	if symKeyGiven {
// 		if keySym, err = api.c.GetSymKey(req.SymKeyID); err != nil {
// 			return "", err
// 		}
// 		if !validateDataIntegrity(keySym, aesKeyLength) {
// 			return "", ErrInvalidSymmetricKey
// 		}
// 	}

// 	if asymKeyGiven {
// 		if keyAsym, err = api.c.GetPrivateKey(req.PrivateKeyID); err != nil {
// 			return "", err
// 		}
// 	}

// 	if len(req.Topics) > 0 {
// 		topics = make([][]byte, len(req.Topics))
// 		for i, topic := range req.Topics {
// 			topics[i] = make([]byte, TopicLength)
// 			copy(topics[i], topic[:])
// 		}
// 	}

// 	f := &Filter{
// 		Src:     src,
// 		KeySym:  keySym,
// 		KeyAsym: keyAsym,
// 		// PoW:      req.MinPow,
// 		AllowP2P: req.AllowP2P,
// 		Topics:   topics,
// 		Messages: make(map[common.Hash]*ReceivedMessage),
// 	}

// 	id, err := api.c.Subscribe(f)
// 	if err != nil {
// 		return "", err
// 	}

// 	api.mu.Lock()
// 	api.lastUsed[id] = time.Now()
// 	api.mu.Unlock()

// 	return id, nil
// }
