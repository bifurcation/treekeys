package treekeys

import (
	"fmt"
	"reflect"
	"testing"
	//"time"
)

func TestPerformance(t *testing.T) {
	// Uncomment for performance test
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

func TestProtoMAC(t *testing.T) {
	key := []byte{0, 1, 2, 3}

	// TODO Populate some fields
	sm := &SetupMessage{}
	msm, err := NewMACMessage(key, sm)
	if err != nil {
		t.Fatalf("Setup MAC", err)
	}

	smsm, err := msm.ToSetupMessage()
	if err != nil {
		t.Fatalf("Setup Verify", err)
	}

	if !reflect.DeepEqual(sm, smsm) {
		t.Fatalf("Setup Mismatch [%+v] [%+v]", sm, smsm)
	}

	// TODO Populate some fields
	um := &UpdateMessage{}
	mum, err := NewMACMessage(key, um)
	if err != nil {
		t.Fatalf("Setup MAC", err)
	}

	umum, err := mum.ToUpdateMessage()
	if err != nil {
		t.Fatalf("Setup Verify", err)
	}

	if !reflect.DeepEqual(um, umum) {
		t.Fatalf("Setup Mismatch [%+v] [%+v]", um, umum)
	}
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
	var sm []*MACMessage
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

func TestProtoAdd(t *testing.T) {
	maxPeers := (1 << 6) - 1

	peers := make([]*Endpoint, maxPeers)
	for i := range peers {
		peers[i] = NewEndpoint()
	}

	// List of states that will get filled as we add peers
	π := make([]*GroupState, maxPeers)

	// Start up a peer-to-peer session
	var sm []*MACMessage
	fmt.Printf("=== Setup ===\n")
	π[0], sm = peers[0].SetupGroup(peers[1:2])
	fmt.Printf("=== ProcessSetup ===\n")
	π[1] = peers[1].ProcessSetupMessage(sm[0])
	if π[0].tk != π[1].tk {
		t.Fatalf("Init tree key mismatch %x %x", π[0].tk, π[1].tk)
	}
	if π[0].sk != π[1].sk {
		t.Fatalf("Init stage key mismatch %x %x", π[0].sk, π[1].sk)
	}
	if !reflect.DeepEqual(π[0].F, π[1].F) {
		t.Logf("Init frontier mismatch")
	}

	for i := range peers {
		fmt.Printf("===> %d\n", i)
		if i == 0 || i == 1 {
			continue
		}

		// Have the last-added peer add the next peer and verify that they both
		// update to the same keys and frontiers
		fmt.Printf("Sending from %d?\n", i-1)
		sm, am := π[i-1].AddPeer(peers[i])
		π[i] = peers[i].ProcessSetupMessage(sm)
		if π[i-1].tk != π[i].tk {
			t.Logf("New peer tree key mismatch after add %d [%x] [%x]", i, π[i-1].tk, π[i].tk)
		}
		if π[i-1].sk != π[i].sk {
			t.Logf("New peer tree key mismatch after add %d [%x] [%x]", i, π[i-1].sk, π[i].sk)
		}
		if !reflect.DeepEqual(π[i-1].F, π[i].F) {
			t.Logf("New peer frontier mismatch after add %d", i)
		}

		// Update the other peers and verify that they get the same keys and
		// frontiers as the initiating peer (and thus transitively the new peer)
		for j := range peers {
			if j >= i-1 {
				continue
			}

			fmt.Printf("Adding at %d\n", j)

			π[j].ProcessAddMessage(am)
			if π[i-1].tk != π[j].tk {
				t.Logf("Old peer tree key mismatch after add %d [%x] [%x]", i, π[i-1].tk, π[j].tk)
			}
			if π[i-1].sk != π[j].sk {
				t.Logf("Old peer stage key mismatch after add %d [%x] [%x]", i, π[i-1].sk, π[j].sk)
			}
			if !reflect.DeepEqual(π[i-1].F, π[i].F) {
				t.Logf("New peer frontier mismatch after add %d", i)
			}
		}
	}
}
