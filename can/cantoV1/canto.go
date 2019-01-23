package canto

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/sync/syncmap"
)

const {
	StatusMsg             = 0x00
	PassthroughMsg        = 0x01
}

type Canto struct {
	chainID       uint64
	subnetAddress uint64
	stakedAmount  uint64
	Validator     bool
	SubnetAllowed bool

	protocol p2p.Protocol
	// filters  *Filters // Message filters installed with Subscribe function

	peerMu sync.RWMutex
	peers  map[*Peer]struct{}

	privateKeys map[string]*ecdsa.PrivateKey // Private key storage
	symKeys     map[string][]byte            // Symmetric key storage
	keyMu       sync.RWMutex                 // Mutex associated with key storages

	syncAllowance int // maximum time in seconds allowed to process the canto-related messages

	settings syncmap.Map // holds configuration settings that can be dynamically changed

	statsMu sync.Mutex    // guard stats
	stats   Statistics    // Statistics of canto node
	quit    chan struct{} // Channel used for graceful exit
}

// Statistics holds several message-related counter for analytics
// purposes.
type Statistics struct {
	messagesCleared      int
	memoryCleared        int
	memoryUsed           int
	addressList          map[string]string
	cycles               int
	totalMessagesCleared int
}

const (
	lightClientModeIdx                       = iota // Light client mode. (does not forward any messages)
	restrictConnectionBetweenLightClientsIdx        // Restrict connection between two light clients
)

// MakeProtocols creates a Canto client ready to communicate through the Ethereum P2P network.
func MakeProtocols(cfg *Config) *Canto {
	if cfg == nil {
		cfg = &DefaultConfig
	}

	canto := &Canto{
		chainID:       1,
		stakedAmount:  0,
		Validator:     false,
		SubnetAllowed: false,
		privateKeys:   make(map[string]*ecdsa.PrivateKey),
		symKeys:       make(map[string][]byte),
		peers:         make(map[*Peer]struct{}),
		quit:          make(chan struct{}),
		syncAllowance: DefaultSyncAllowance,
	}

	// canto.filters = NewFilters(canto)
	canto.settings.Store(restrictConnectionBetweenLightClientsIdx, cfg.RestrictConnectionBetweenLightClients)
	// canto.settings.Store()

	// p2p whisper sub protocol handler
	canto.protocol = p2p.Protocol{
		Name:    ProtocolName,
		Version: uint(ProtocolVersion),
		Length:  NumberOfMessageCodes,
		Run:     canto.HandlePeer,
		NodeInfo: func() interface{} {
			return map[string]interface{}{
				"version":       "1",
				"validator":     canto.IsValidator(),
				"subnetAllowed": canto.IsSubnetAllowed(),
				// what are the other things that need to initialized for p2p.Protocol?
			}
		},
	}
	return canto
}

// IsValidator checks if this canto node is a validator
func (canto *Canto) IsValidator() bool {
	return canto.Validator
}

// IsSubnetAllowed checks if the canto node is allowed to access Subnets
func (canto *Canto) IsSubnetAllowed() bool {
	return canto.SubnetAllowed
}

// func (canto *Canto) stakeSubnetAccess() error {
// 	transaction.NewTransaction(block.TxNonce(testBankAddress), acc1Addr, big.NewInt(10000), params.TxGas, nil, nil), signer, testBankKey)
// 	// newTransaction(nonce, &to, amount, gasLimit, gasPrice, data)
// }

// HandlePeer is called by the underlying P2P layer when the canto sub-protocol
// connection is negotiated.
func (canto *Canto) HandlePeer(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	// Create the new peer and start tracking it
	cantoPeer := newPeer(canto, peer, rw)

	canto.peerMu.Lock()
	canto.peers[cantoPeer] = struct{}{}
	canto.peerMu.Unlock()

	defer func() {
		canto.peerMu.Lock()
		delete(canto.peers, cantoPeer)
		canto.peerMu.Unlock()
	}()

	// Run the peer handshake and state updates
	if err := cantoPeer.handshake(); err != nil {
		return err
	}
	// seems like the Start() method is required to start the subprotocol
	cantoPeer.start()
	defer cantoPeer.stop()

	return canto.runMessageLoop(cantoPeer, rw)
}

func (canto *Canto) runMessageLoop(peer *p2p.Peer rw p2p.MsgReadWriter) error {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	p.Log().Trace("Canto message arrived", "code", msg.Code, "bytes", msg.Size)

	switch msg.Code {
	case StatusMsg:
		p.Log().Trace("Received status message")
		// Status messages should never arrive after the handshake
		return errResp(ErrExtraStatusMsg, "uncontrolled status message")
	case PassthroughMsg:
		p.Log().Trace("Received passthrough message")
	}
}

// APIs returns the RPC descriptors the Canto implementation offers
func (canto *Canto) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: ProtocolName,
			Version:   ProtocolVersionStr,
			Service:   NewPublicCantoAPI(canto),
			Public:    true,
		},
	}
}

// Protocols returns the canto sub-protocols ran by this particular client.
func (canto *Canto) Protocols() []p2p.Protocol {
	return []p2p.Protocol{canto.protocol}
}

// Version returns the canto sub-protocols version number.
func (canto *Canto) Version() uint {
	return canto.protocol.Version
}

//SetLightClientMode makes node light client (does not forward any messages)
func (canto *Canto) SetLightClientMode(v bool) {
	canto.settings.Store(lightClientModeIdx, v)
}

//LightClientMode indicates is this node is light client (does not forward any messages)
func (canto *Canto) LightClientMode() bool {
	val, exist := canto.settings.Load(lightClientModeIdx)
	if !exist || val == nil {
		return false
	}
	v, ok := val.(bool)
	return v && ok
}

//LightClientModeConnectionRestricted indicates that connection to light client in light client mode not allowed
func (canto *Canto) LightClientModeConnectionRestricted() bool {
	val, exist := canto.settings.Load(restrictConnectionBetweenLightClientsIdx)
	if !exist || val == nil {
		return false
	}
	v, ok := val.(bool)
	return v && ok
}

func (canto *Canto) notifyPeersAboutPeerListChange(peerList map[*Peer]struct{}) {
	arr := canto.getPeers()
	for _, p := range arr {
		err := p.notifyAboutPeerListChange(peerList)
		if err != nil {
			// allow one retry
			err = p.notifyAboutPeerListChange(peerList)
		}
		if err != nil {
			log.Warn("failed to notify peer about peer list", "peer", p.ID(), "error", err)
		}
	}
}

func (canto *Canto) getPeers() []*Peer {
	arr := make([]*Peer, len(canto.peers))
	i := 0
	canto.peerMu.Lock()
	for p := range canto.peers {
		arr[i] = p
		i++
	}
	canto.peerMu.Unlock()
	return arr
}

// getPeer retrieves peer by ID
func (canto *Canto) getPeer(peerID []byte) (*Peer, error) {
	canto.peerMu.Lock()
	defer canto.peerMu.Unlock()
	for p := range canto.peers {
		id := p.peer.ID()
		if bytes.Equal(peerID, id[:]) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("Could not find peer with ID: %x", peerID)
}

// AllowP2PMessagesFromPeer marks specific peer trusted,
// which will allow it to send historic (expired) messages.
func (canto *Canto) AllowP2PMessagesFromPeer(peerID []byte) error {
	p, err := canto.getPeer(peerID)
	if err != nil {
		return err
	}
	p.trusted = true
	return nil
}

// Start implements node.Service, starting the background data propagation thread
// of the Canto protocol.
func (canto *Canto) Start(*p2p.Server) error {
	log.Info("started canto v." + ProtocolVersionStr)
	// go canto.update()

	// numCPU := runtime.NumCPU()
	// for i := 0; i < numCPU; i++ {
	// 	go canto.processQueue()
	// }

	return nil
}

// Stop implements node.Service, stopping the background data propagation thread
// of the Whisper protocol.
func (canto *Canto) Stop() error {
	close(canto.quit)
	log.Info("canto stopped")
	return nil
}

// Stats returns the whisper node statistics.
func (canto *Canto) Stats() Statistics {
	canto.statsMu.Lock()
	defer canto.statsMu.Unlock()

	return canto.stats
}

// reset resets the node's statistics after each expiry cycle.
func (s *Statistics) reset() {
	s.cycles++
	s.totalMessagesCleared += s.messagesCleared

	s.memoryCleared = 0
	s.messagesCleared = 0
}

// ValidatePublicKey checks the format of the given public key.
func ValidatePublicKey(k *ecdsa.PublicKey) bool {
	return k != nil && k.X != nil && k.Y != nil && k.X.Sign() != 0 && k.Y.Sign() != 0
}

// validatePrivateKey checks the format of the given private key.
func validatePrivateKey(k *ecdsa.PrivateKey) bool {
	if k == nil || k.D == nil || k.D.Sign() == 0 {
		return false
	}
	return ValidatePublicKey(&k.PublicKey)
}

// containsOnlyZeros checks if the data contain only zeros.
func containsOnlyZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

// bytesToUintLittleEndian converts the slice to 64-bit unsigned integer.
func bytesToUintLittleEndian(b []byte) (res uint64) {
	mul := uint64(1)
	for i := 0; i < len(b); i++ {
		res += uint64(b[i]) * mul
		mul *= 256
	}
	return res
}

// BytesToUintBigEndian converts the slice to 64-bit unsigned integer.
func BytesToUintBigEndian(b []byte) (res uint64) {
	for i := 0; i < len(b); i++ {
		res *= 256
		res += uint64(b[i])
	}
	return res
}

// GenerateRandomID generates a random string, which is then returned to be used as a key id
// func GenerateRandomID() (id string, err error) {
// 	buf, err := generateSecureRandomData(keyIDSize)
// 	if err != nil {
// 		return "", err
// 	}
// 	if !validateDataIntegrity(buf, keyIDSize) {
// 		return "", fmt.Errorf("error in generateRandomID: crypto/rand failed to generate random data")
// 	}
// 	id = common.Bytes2Hex(buf)
// 	return id, err
// }
