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
	"fmt"
	"sync"
	"time"

	// mapset "github.com/deckarep/golang-set"
	mapset "github.com/deckarep/golang-set"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rlp"
)

// Peer represents a Canto protocol peer connection.
type Peer struct {
	host *Canto
	peer *p2p.Peer
	ws   p2p.MsgReadWriter

	subnetAllowed bool

	trusted     bool
	bloomMu     sync.Mutex
	bloomFilter []byte
	fullNode    bool

	known mapset.Set // Messages already known by the peer to avoid wasting bandwidth

	quit chan struct{}
}

// newPeer creates a new Canto peer object, but does not run the handshake itself.
func newPeer(host *Canto, remote *p2p.Peer, rw p2p.MsgReadWriter) *Peer {
	return &Peer{
		host:          host,
		peer:          remote,
		ws:            rw,
		subnetAllowed: false,
		trusted:       false,
		known:         mapset.NewSet(),
		quit:          make(chan struct{}),
		// bloomFilter:   MakeFullNodeBloom(),
		fullNode: true,
	}
}

// start initiates the peer updater, periodically broadcasting the Canto packets
// into the network.
func (peer *Peer) start() {
	go peer.update()
	log.Trace("start", "peer", peer.ID())
}

// stop terminates the peer updater, stopping message forwarding to it.
func (peer *Peer) stop() {
	close(peer.quit)
	log.Trace("stop", "peer", peer.ID())
}

// handshake sends the protocol initiation status message to the remote peer and
// verifies the remote status too.
func (peer *Peer) handshake() error {
	// Send the handshake status message asynchronously
	errc := make(chan error, 1)
	isLightNode := peer.host.LightClientMode()
	isRestrictedLightNodeConnection := peer.host.LightClientModeConnectionRestricted()
	go func() {
		// bloom := peer.host.BloomFilter()

		errc <- p2p.SendItems(peer.ws, statusCode, ProtocolVersion, isLightNode)
	}()

	// Fetch the remote status packet and verify protocol match
	packet, err := peer.ws.ReadMsg()
	if err != nil {
		return err
	}
	if packet.Code != statusCode {
		return fmt.Errorf("peer [%x] sent packet %x before status packet", peer.ID(), packet.Code)
	}
	s := rlp.NewStream(packet.Payload, uint64(packet.Size))
	_, err = s.List()
	if err != nil {
		return fmt.Errorf("peer [%x] sent bad status message: %v", peer.ID(), err)
	}
	peerVersion, err := s.Uint()
	if err != nil {
		return fmt.Errorf("peer [%x] sent bad status message (unable to decode version): %v", peer.ID(), err)
	}
	if peerVersion != ProtocolVersion {
		return fmt.Errorf("peer [%x]: protocol version mismatch %d != %d", peer.ID(), peerVersion, ProtocolVersion)
	}

	if err == nil {
	}

	isRemotePeerLightNode, err := s.Bool()
	if isRemotePeerLightNode && isLightNode && isRestrictedLightNodeConnection {
		return fmt.Errorf("peer [%x] is useless: two light client communication restricted", peer.ID())
	}

	if err := <-errc; err != nil {
		return fmt.Errorf("peer [%x] failed to send status packet: %v", peer.ID(), err)
	}
	return nil
}

// update executes periodic operations on the peer, including message transmission
// and expiration.
func (peer *Peer) update() {
	// Start the tickers for the updates
	// expire := time.NewTicker(expirationCycle)
	transmit := time.NewTicker(transmissionCycle)

	// Loop and transmit until termination is requested
	for {
		select {
		// case <-expire.C:
		// 	peer.expire()

		case <-transmit.C:
			if err := peer.broadcast(); err != nil {
				log.Trace("broadcast failed", "reason", err, "peer", peer.ID())
				return
			}

		case <-peer.quit:
			return
		}
	}
}

// mark marks an envelope known to the peer so that it won't be sent back.
// func (peer *Peer) mark(envelope *Envelope) {
// 	peer.known.Add(envelope.Hash())
// }

// marked checks if an envelope is already known to the remote peer.
// func (peer *Peer) marked(envelope *Envelope) bool {
// 	return peer.known.Contains(envelope.Hash())
// }

// expire iterates over all the known envelopes in the host and removes all
// expired (unknown) ones from the known list.
// func (peer *Peer) expire() {
// 	unmark := make(map[common.Hash]struct{})
// 	peer.known.Each(func(v interface{}) bool {
// 		// if !peer.host.isEnvelopeCached(v.(common.Hash)) {
// 		// 	unmark[v.(common.Hash)] = struct{}{}
// 		// }
// 		return true
// 	})
// 	// Dump all known but no longer cached
// 	for hash := range unmark {
// 		peer.known.Remove(hash)
// 	}
// }

// broadcast iterates over the collection of envelopes and transmits yet unknown
// ones over the network.
func (peer *Peer) broadcast() error {
	// broadcast peer List
	// code this part later

	// envelopes := peer.host.Envelopes()
	// bundle := make([]*Envelope, 0, len(envelopes))

	// if len(bundle) > 0 {
	// 	// transmit the batch of envelopes
	// 	if err := p2p.Send(peer.ws, messagesCode, bundle); err != nil {
	// 		return err
	// 	}

	// 	// mark envelopes only if they were successfully sent
	// 	for _, e := range bundle {
	// 		peer.mark(e)
	// 	}

	// 	log.Trace("broadcast", "num. messages", len(bundle))
	// }
	return nil
}

// ID returns a peer's id
func (peer *Peer) ID() []byte {
	id := peer.peer.ID()
	return id[:]
}

func (peer *Peer) notifyAboutPeerListChange(peerList map[*Peer]struct{}) error {
	return p2p.Send(peer.ws, peerListUpdateExCode, peerList)
}
