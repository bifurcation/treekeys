package treekeys

import (
	"testing"
)

func TestProtoSetup(t *testing.T) {
	nPeers := 15

	peers := make([]*Endpoint, nPeers)
	for i := range peers {
		peers[i] = NewEndpoint()
	}

	// Peer 0 initiates to the rest of the peers
	π0, m := peers[0].SetupGroup(peers[1:])

	// Verify that when each peer receives its setup message, it computes the
	// same tree key that the first peer did
	for i := range peers {
		if i == 0 {
			continue
		}

		π := peers[i].ProcessSetupMessage(m[i-1])
		if π.tk != π0.tk {
			t.Fatalf("Tree key mismatch [%d]", i)
		}
	}
}
