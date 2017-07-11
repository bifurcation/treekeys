package treekeys

type TreeNode struct {
	Left  *TreeNode
	Right *TreeNode
	Value PrivateKey
	Size  int
}

func (t TreeNode) IsLeaf() bool {
	return t.Left == nil && t.Right == nil
}

func CreateTree(λ []PrivateKey) *TreeNode {
	n := len(λ)
	if n == 1 {
		return &TreeNode{Left: nil, Right: nil, Value: λ[0], Size: 1}
	}

	m := pow2(n)
	L := CreateTree(λ[0:m])
	R := CreateTree(λ[m:n])

	k := ι(Exp(PK(L.Value), R.Value))
	return &TreeNode{Left: L, Right: R, Value: k, Size: L.Size + R.Size}
}

func Copath(T *TreeNode, i int) []GroupElement {
	// XXX Stop condition not listed in paper
	if T.IsLeaf() {
		return []GroupElement{}
	}

	m := pow2(T.Size)

	var key GroupElement
	var remainder []GroupElement
	if i < m {
		key = PK(T.Right.Value)
		remainder = Copath(T.Left, i)
	} else {
		key = PK(T.Left.Value)
		remainder = Copath(T.Right, i-m)
	}

	return append([]GroupElement{key}, remainder...)
}

type FrontierEntry struct {
	SubtreeSize int
	Value       GroupElement
}

type Frontier []FrontierEntry

func (f *Frontier) Add(λ PrivateKey) {
	// Append to frontier
	priv := λ
	val := PK(priv)

	*f = append(*f, FrontierEntry{1, val})

	// Compact
	if len(*f) < 2 {
		return
	}

	n := len(*f)
	for n > 1 {
		last := (*f)[n-1]
		nextToLast := (*f)[n-2]

		if last.SubtreeSize != nextToLast.SubtreeSize {
			break
		}

		n -= 1
		priv = ι(Exp(nextToLast.Value, priv))
		val := PK(priv)

		(*f)[n-1] = FrontierEntry{
			SubtreeSize: last.SubtreeSize + nextToLast.SubtreeSize,
			Value:       val,
		}
	}

	(*f) = (*f)[:n]
}

func (f Frontier) ToPath() []GroupElement {
	P := make([]GroupElement, len(f))
	for i, entry := range f {
		P[i] = entry.Value
	}
	return P
}

func (T *TreeNode) Frontier() Frontier {
	if T.IsLeaf() || isPow2(T.Size) {
		return Frontier{FrontierEntry{T.Size, PK(T.Value)}}
	}

	f := Frontier{FrontierEntry{T.Left.Size, PK(T.Left.Value)}}
	return append(f, T.Right.Frontier()...)
}

func PathNodeKeys(λ PrivateKey, P []GroupElement) []PrivateKey {
	nks := make([]PrivateKey, len(P)+1)
	nks[len(P)] = λ
	for n := len(P) - 1; n >= 0; n -= 1 {
		nks[n] = ι(Exp(P[n], nks[n+1]))
	}
	return nks
}
