// Copyright 2019 The go-ethereum Authors
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

package cto

import (
	"github.com/ethereum/go-ethereum/p2p"
)

type cantoCommons struct {
	chainId uint64
}

func (c *cantoCommons) makeProtocols(versions []uint) []p2p.Protocol {
	protos := make([]p2p.Protocol, len(versions))
	for i, version := range versions {
		version := version
		protos[i] = p2p.Protocol{
			Name:    "can",
			Version: version,
			Length:  1,
			NodeInfo: func() interface{} {
				return map[string]interface{}{
					"version": "1",
				}
			},
			// Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
			// 	return c.cantoBackend.runPeer(version, p, rw)
			// },
			// PeerInfo: func(id enode.ID) interface{} {
			// 	if p := c.cantoBackend.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
			// 		return p.Info()
			// 	}
			// 	return nil
			// },
		}
	}
	return protos
}
