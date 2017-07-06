package treekeys

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

type GroupState struct {
	i  int
	ik PrivateKey
	λ  PrivateKey
	ID []GroupElement
	P  []GroupElement
	tk PrivateKey
}

type SetupMessage struct {
	i  int
	ID []GroupElement
	EK GroupElement
	Ks GroupElement
	P  []GroupElement
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
			i:  i,
			ID: π.ID,
			EK: EK[i],
			Ks: PK(ks),
			P:  Copath(T, i+1),
		}
		// XXX Not computing MAC because it will never be verified
	}

	π.tk = T.Value
	π.P = Copath(T, 0)

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
	return π
}

/*
type UpdateMessage struct {
	j int
	U GroupElement
}

func (π *GroupState) UpdateKey() UpdateMessage {

}
*/
