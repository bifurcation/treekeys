package treekeys

import (
	"encoding/json"
	"fmt"
)

type Endpoint struct {
	identityKey PrivateKey
	preKeys     map[GroupElement]PrivateKey

	// State for a group
	roster []GroupElement
	copath []GroupElement
	λ      PrivateKey
	tk     PrivateKey
}

func NewEndpoint() *Endpoint {
	return &Endpoint{
		identityKey: DHKeyGen(),
		preKeys:     map[GroupElement]PrivateKey{},
	}
}

func (e *Endpoint) PreKey() GroupElement {
	ek := DHKeyGen()
	EK := PK(ek)
	e.preKeys[EK] = ek
	return EK
}

func (e Endpoint) Identity() GroupElement {
	return PK(e.identityKey)
}

/////

type SetupMessage struct {
	I    int
	From int
	ID   []GroupElement
	EK   GroupElement
	Ks   GroupElement
	P    []GroupElement
	F    Frontier
	SK   PrivateKey
}

type UpdateMessage struct {
	J int
	U []GroupElement
}

type AddMessage struct {
	ID GroupElement
	U  []GroupElement
	F  Frontier
}

type MACMessage struct {
	// XXX Should probably have an indicator of message type that is covered by the MAC
	Message []byte
	MAC     []byte
}

func NewMACMessage(key []byte, msg interface{}) (*MACMessage, error) {
	var err error
	macmsg := &MACMessage{}

	macmsg.Message, err = json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	macmsg.MAC = MAC(key[:], macmsg.Message)
	return macmsg, nil
}

func (macmsg MACMessage) Verify(key []byte) bool {
	return VerifyMAC(key, macmsg.Message, macmsg.MAC)
}

func (macmsg MACMessage) ToSetupMessage() (*SetupMessage, error) {
	var msg SetupMessage
	err := json.Unmarshal(macmsg.Message, &msg)
	return &msg, err
}

func (macmsg MACMessage) ToUpdateMessage() (*UpdateMessage, error) {
	var msg UpdateMessage
	err := json.Unmarshal(macmsg.Message, &msg)
	return &msg, err
}

func (macmsg MACMessage) ToAddMessage() (*AddMessage, error) {
	var msg AddMessage
	err := json.Unmarshal(macmsg.Message, &msg)
	return &msg, err
}

/////

type GroupState struct {
	i  int
	ik PrivateKey
	λ  PrivateKey
	ID []GroupElement
	P  []GroupElement
	tk PrivateKey
	sk PrivateKey
	F  Frontier
}

func (e *Endpoint) SetupGroup(peers []*Endpoint) (*GroupState, []*MACMessage) {
	nPeers := len(peers)

	π := &GroupState{}
	π.ik = e.identityKey
	π.i = 0

	π.λ = DHKeyGen()
	ks := KeyExchangeKeyGen()

	IK := make([]GroupElement, nPeers)
	EK := make([]GroupElement, nPeers)
	λ := make([]PrivateKey, nPeers)
	for i, peer := range peers {
		IK[i] = peer.Identity()
		EK[i] = peer.PreKey()
		λ[i] = ι(PK(KeyExchange(true, π.ik, IK[i], ks, EK[i])))
	}

	T := CreateTree(append([]PrivateKey{π.λ}, λ...))
	π.ID = append([]GroupElement{PK(π.ik)}, IK...)
	π.tk = T.Value
	π.sk = DHKeyGen() // XXX Not in paper
	π.P = Copath(T, 0)

	π.F = T.Frontier()

	m := make([]*MACMessage, nPeers)
	for i := range peers {
		sm := SetupMessage{
			I:    i + 1,
			From: 0,
			ID:   π.ID,
			EK:   EK[i],
			Ks:   PK(ks),
			P:    Copath(T, i+1),
			F:    π.F,
			SK:   π.sk, // XXX Not in paper
		}

		// XXX Ignoring error
		m[i], _ = NewMACMessage(λ[i][:], sm)
	}

	// XXX How should π.sk be initialized on group creation?  This just assumes
	// it is set to the all-zero vector, and combined with the π.sk immediately.
	π.DeriveStageKey()

	return π, m
}

func (e *Endpoint) ProcessSetupMessage(macmsg *MACMessage) *GroupState {
	π := &GroupState{}
	π.ik = e.identityKey

	// XXX Paper doesn't specify verifying MAC
	// XXX Ignoring error
	msg, _ := macmsg.ToSetupMessage()

	ek, ok := e.preKeys[msg.EK]
	if !ok {
		// TODO: Handle this better
		panic("Unknown PreKey")
	}

	π.λ = ι(PK(KeyExchange(false, π.ik, msg.ID[msg.From], ek, msg.Ks)))
	if !macmsg.Verify(π.λ[:]) {
		panic("Bad MAC")
	}

	// XXX Paper doesn't specify doing anything with i
	π.i = msg.I
	π.ID = msg.ID
	π.P = msg.P
	π.F = msg.F
	π.sk = msg.SK // XXX Not in paper

	nks := PathNodeKeys(π.λ, π.P)
	π.tk = nks[0]

	// XXX How should π.sk be initialized on group creation?  This just assumes
	// it is set to the all-zero vector, and combined with the π.sk immediately.
	π.DeriveStageKey()

	return π
}

func (π *GroupState) UpdateKey() *MACMessage {
	π.λ = DHKeyGen()
	nks := PathNodeKeys(π.λ, π.P)

	// XXX Not computing MAC because it will never be verified
	// XXX π.sk is used as the MAC key but never computed
	um := UpdateMessage{
		J: π.i,
		U: make([]GroupElement, len(π.P)),
	}
	for i, nk := range nks {
		if i == 0 {
			continue
		}

		um.U[i-1] = PK(nk)
	}

	// XXX Ignoring error
	mm, _ := NewMACMessage(π.sk[:], um)

	// XXX Assuming stage key update happens every time the tree key changes?
	π.tk = nks[0]
	π.DeriveStageKey()

	return mm
}

// XXX This is completely upside-down compared to the paper.  I think the paper
// is just wrong here; it acts as if the node-key and copath list were ordered
// starting from the leaves.  They actually start from the root, so we need to
// count down from the root, instead of starting with the height and
// decrementing to the right place.
func IndexToUpdate(d, n, i, j int) int {
	if i == j {
		panic(fmt.Sprintf("Equal indices passed to IndexToUpdate [%d] [%d]", i, j))
	}

	m := pow2(n)

	switch {
	case i < m && j < m:
		return IndexToUpdate(d+1, m, i, j)
	case i >= m && j >= m:
		return IndexToUpdate(d+1, n-m, i-m, j-m)
	}

	return d
}

func (π *GroupState) ProcessUpdateMessage(macmsg *MACMessage) {
	if !macmsg.Verify(π.sk[:]) {
		panic("Bad MAC")
	}

	// XXX Ignoring error
	msg, _ := macmsg.ToUpdateMessage()

	d := IndexToUpdate(0, len(π.ID), π.i, msg.J)

	π.P[d] = msg.U[d]
	nks := PathNodeKeys(π.λ, π.P)
	π.tk = nks[0]

	// XXX Assuming this happens every time the tree key changes?
	π.DeriveStageKey()

	return
}

func (π *GroupState) DeriveStageKey() {
	idBytes := []byte{}
	for _, id := range π.ID {
		idBytes = append(idBytes, id[:]...)
	}

	oldsk := π.sk
	π.sk = KDF(π.sk[:], π.tk[:] /*XXX, idBytes*/)

	fmt.Printf("sk: %d : [%x] + [%x] -> [%x]\n", π.i, oldsk[:5], π.tk[:5], π.sk[:5])
}

///////// XXX Everything below this line is RLB addition //////////

func (π *GroupState) AddPeer(peer *Endpoint) (setup *MACMessage, add *MACMessage) {
	// Do key exchange
	IK := peer.Identity()
	EK := peer.PreKey()
	ks := KeyExchangeKeyGen()
	λ := ι(PK(KeyExchange(true, π.ik, IK, ks, EK)))

	// Compute the new copath and frontier
	P := π.F.ToPath()
	newF := π.F
	newF.Add(λ)
	oldSK := π.sk

	// Compute an update path to the new node
	nks := PathNodeKeys(λ, P)
	U := make([]GroupElement, len(P))
	for i, nk := range nks {
		if i == 0 {
			continue
		}

		U[i-1] = PK(nk)
	}

	// Compute add message and update ourselves
	am := AddMessage{
		ID: IK,
		U:  U,
		F:  newF,
	}

	mam, err := NewMACMessage(π.sk[:], am)
	if err != nil {
		// TODO handle more elegantly
		panic(fmt.Sprintf("MAC error %v", err))
	}

	π.ProcessAddMessage(mam)

	// Compute setup message for new peer
	// XXX Need to provide initial stage key, but this is confidential :/
	// XXX Note that if we just send the initial SK in the setup message, then it
	// also removes some ambiguity from raw setup.  But then we need AEAD on
	// setup messages, not just MAC.  That's fine though, since we have the keys
	// handy already.
	// XXX: Ignoring errors
	fmt.Printf("Sending from %d -> %d.\n", π.i, len(π.ID)-1)
	sm := SetupMessage{
		I:    len(π.ID) - 1,
		From: π.i,
		ID:   π.ID,
		EK:   EK,
		Ks:   PK(ks),
		P:    P,
		F:    newF,
		SK:   oldSK,
	}

	msm, err := NewMACMessage(λ[:], sm)
	if err != nil {
		// TODO handle more elegantly
		panic(fmt.Sprintf("MAC error %v", err))
	}

	// Update ourselves

	return msm, mam
}

func (π *GroupState) ProcessAddMessage(macmsg *MACMessage) {
	if !macmsg.Verify(π.sk[:]) {
		panic("Bad MAC")
	}

	// XXX Ignoring error
	msg, _ := macmsg.ToAddMessage()
	π.ID = append(π.ID, msg.ID)
	π.F = msg.F

	// If we're in the rightmost subtree before the addition, we get pushed down,
	// i.e., we insert an element into the copath for the newly-added element.
	n := len(π.ID) - 1
	log := uint(0)
	for (n>>log)&0x01 == 0 {
		log += 1
	}

	if n-π.i <= (1 << log) {
		toInsert := msg.U[len(msg.U)-1]
		split := len(π.P) - int(log)
		first := π.P[:split]
		last := π.P[split:]
		insert := []GroupElement{toInsert}
		π.P = append(first, append(insert, last...)...)
	}

	// Otherwise this just looks like a key update
	d := IndexToUpdate(0, len(π.ID), π.i, len(π.ID)-1)
	π.P[d] = msg.U[d]

	nks := PathNodeKeys(π.λ, π.P)
	π.tk = nks[0]
	π.DeriveStageKey()

	return
}
