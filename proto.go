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
	i  int
	ID []GroupElement
	EK GroupElement
	Ks GroupElement
	P  []GroupElement
}

type UpdateMessage struct {
	j int
	U []GroupElement
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

func (macmsg MACMessage) ToSetupMessage(key []byte) (*SetupMessage, error) {
	if !VerifyMAC(key, macmsg.Message, macmsg.MAC) {
		return nil, fmt.Errorf("MAC verify failure [setup]")
	}

	var msg SetupMessage
	err := json.Unmarshal(macmsg.Message, &msg)
	return &msg, err
}

func (macmsg MACMessage) ToUpdateMessage(key []byte) (*UpdateMessage, error) {
	if !VerifyMAC(key, macmsg.Message, macmsg.MAC) {
		return nil, fmt.Errorf("MAC verify failure [update]")
	}

	var msg UpdateMessage
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
}

func (e *Endpoint) SetupGroup(peers []*Endpoint) (*GroupState, []SetupMessage) {
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

	m := make([]SetupMessage, nPeers)
	for i := range peers {
		m[i] = SetupMessage{
			i:  i + 1,
			ID: π.ID,
			EK: EK[i],
			Ks: PK(ks),
			P:  Copath(T, i+1),
		}
		// XXX Not computing MAC because it will never be verified
	}

	π.tk = T.Value
	π.P = Copath(T, 0)

	// XXX How should π.sk be initialized on group creation?  This just assumes
	// it is set to the all-zero vector, and combined with the π.sk immediately.
	π.DeriveStageKey()

	return π, m
}

func (e *Endpoint) ProcessSetupMessage(msg SetupMessage) *GroupState {
	// XXX Paper doesn't specify verifying MAC
	// XXX Paper doesn't specify doing anything with i
	π := &GroupState{}
	π.ik = e.identityKey
	π.i = msg.i
	π.ID = msg.ID
	π.P = msg.P

	ek, ok := e.preKeys[msg.EK]
	if !ok {
		// TODO: Handle this better
		panic("Unknown PreKey")
	}

	// XXX PK conversion differs from paper
	π.λ = ι(PK(KeyExchange(false, π.ik, msg.ID[0], ek, msg.Ks)))
	nks := PathNodeKeys(π.λ, π.P)
	π.tk = nks[0]

	// XXX How should π.sk be initialized on group creation?  This just assumes
	// it is set to the all-zero vector, and combined with the π.sk immediately.
	π.DeriveStageKey()

	return π
}

func (π *GroupState) UpdateKey() UpdateMessage {
	π.λ = DHKeyGen()
	nks := PathNodeKeys(π.λ, π.P)

	// XXX Not computing MAC because it will never be verified
	// XXX π.sk is used as the MAC key but never computed
	m := UpdateMessage{
		j: π.i,
		U: make([]GroupElement, len(π.P)),
	}
	for i, nk := range nks {
		if i == 0 {
			continue
		}

		m.U[i-1] = PK(nk)
	}

	π.tk = nks[0]

	// XXX Assuming this happens every time the tree key changes?
	π.DeriveStageKey()

	return m
}

// XXX This is completely upside-down compared to the paper.  I think the paper
// is just wrong here; it acts as if the node-key and copath list were ordered
// starting from the leaves.  They actually start from the root, so we need to
// count down from the root, instead of starting with the height and
// decrementing to the right place.
func IndexToUpdate(h, d, i, j int) int {
	pow2h1 := (1 << (uint(h-d) - 1))

	switch {
	case (i < pow2h1) && (j < pow2h1):
		return IndexToUpdate(h, d+1, i, j)
	case (i >= pow2h1) && (j >= pow2h1):
		return IndexToUpdate(h, d+1, i-pow2h1, j-pow2h1)
	}

	return d
}

func (π *GroupState) ProcessUpdateMessage(msg UpdateMessage) {
	h := ceillog2(len(π.ID))
	d := IndexToUpdate(h, 0, π.i, msg.j)

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

	π.sk = KDF(π.sk[:], π.tk[:], idBytes)
}
