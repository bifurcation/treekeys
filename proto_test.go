package treekeys

import (
	//"fmt"
	"testing"
	//"time"
)

func TestPerformance(t *testing.T) {
	/*
		for _, logNPeers := range []uint{2, 3, 7, 10, 15, 17} {
			nPeers := (1 << logNPeers) - 1

			peers := make([]*Endpoint, nPeers)
			for i := range peers {
				peers[i] = NewEndpoint()
			}

			// Peer 0 initiates to the rest of the peers
			beforeSetup := time.Now()
			π0, sm := peers[0].SetupGroup(peers[1:])
			afterSetup := time.Now()

			// Have peer 1 accept the setup message
			beforeProcessSetup := time.Now()
			π1 := peers[1].ProcessSetupMessage(sm[0])
			afterProcessSetup := time.Now()

			// Have peer 0 update its key
			beforeUpdate := time.Now()
			um := π0.UpdateKey()
			afterUpdate := time.Now()

			// Have peer 1 accept the update message
			beforeProcessUpdate := time.Now()
			π1.ProcessUpdateMessage(um)
			afterProcessUpdate := time.Now()

			fmt.Printf("%7d %7d %7d %7d %7d\n",
				nPeers,
				afterSetup.Sub(beforeSetup)/time.Millisecond,
				afterProcessSetup.Sub(beforeProcessSetup)/time.Millisecond,
				afterUpdate.Sub(beforeUpdate)/time.Millisecond,
				afterProcessUpdate.Sub(beforeProcessUpdate)/time.Millisecond)
		}
	*/
}

func TestProtoSetup(t *testing.T) {
	nPeers := 2

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
		if π.sk != π0.sk {
			t.Fatalf("Stage key mismatch [%d]", i)
		}
	}
}

func TestProtoUpdate(t *testing.T) {
	nPeers := 15

	peers := make([]*Endpoint, nPeers)
	for i := range peers {
		peers[i] = NewEndpoint()
	}

	// Setup
	π := make([]*GroupState, nPeers)
	var sm []SetupMessage
	π[0], sm = peers[0].SetupGroup(peers[1:])
	for i := range peers {
		if i == 0 {
			continue
		}

		π[i] = peers[i].ProcessSetupMessage(sm[i-1])
	}

	// Have each endpoint update its key.  At each step, verify that all peers
	// arrive at the same results
	for i := range peers {
		um := π[i].UpdateKey()

		for j := range peers {
			if j == i {
				continue
			}

			π[j].ProcessUpdateMessage(um)
			if π[j].tk != π[i].tk {
				t.Fatalf("Tree key mismatch [%d] [%d]", i, j)
			}
			if π[j].sk != π[i].sk {
				t.Fatalf("Stage key mismatch [%d] [%d]", i, j)
			}
		}
	}
}
