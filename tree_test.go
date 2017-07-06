package treekeys

import (
	"testing"
)

/*
// Use for detailed debugging as needed
func trunc(b [32]byte) []byte {
	return b[:4]
}

func printTree(t *TreeNode, depth int) {
	pad := ""
	for i := 0; i < depth; i += 1 {
		pad += "  "
	}

	fmt.Printf("%sValue: priv=[%x] pub=[%x]\n", pad, trunc(t.Value), trunc(PK(t.Value)))

	if t.Left != nil {
		printTree(t.Left, depth+1)
	}

	if t.Right != nil {
		printTree(t.Right, depth+1)
	}
}
*/

func TestTreeAndPath(t *testing.T) {
	maxPeers := 17

	for nPeers := 1; nPeers <= maxPeers; nPeers += 1 {
		λ := make([]PrivateKey, nPeers)
		for i := range λ {
			λ[i] = DHKeyGen()
		}

		tree := CreateTree(λ)
		if tree.Size() != nPeers {
			t.Fatalf("Wrong tree size [%d] != [%d]", tree.Size(), nPeers)
		}

		for i := range λ {
			P := Copath(tree, i)
			nks := PathNodeKeys(λ[i], P)
			if nks[0] != tree.Value {
				t.Fatalf("Tree key computation failed for node %d [%x] != [%x]", i)
			}
		}
	}
}
