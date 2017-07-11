package treekeys

import (
	//"fmt"
	"reflect"
	"testing"
)

// Use for detailed debugging as needed
/*
func trunc(b [32]byte) []byte {
	return b[:5]
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

func printFrontier(f Frontier) {
	fmt.Printf("=====\n")
	for i, entry := range f {
		fmt.Printf("  %3d %3d %x\n", i, entry.SubtreeSize, trunc(entry.Value))
	}
}
*/

func TestTreeAndPath(t *testing.T) {
	maxPeers := 17
	Λ := make([]PrivateKey, maxPeers)
	for i := range Λ {
		Λ[i] = DHKeyGen()
	}

	incrementalFrontier := Frontier{}

	for nPeers := 1; nPeers <= maxPeers; nPeers += 1 {
		λ := Λ[:nPeers]
		tree := CreateTree(λ)
		if tree.Size != nPeers {
			t.Fatalf("Wrong tree size [%d] != [%d]", tree.Size, nPeers)
		}

		for i := range λ {
			P := Copath(tree, i)
			nks := PathNodeKeys(λ[i], P)
			if nks[0] != tree.Value {
				t.Fatalf("Tree key computation failed for node %d [%x] != [%x]", i)
			}
		}

		f := tree.Frontier()
		fsize := 0
		for _, entry := range f {
			fsize += entry.SubtreeSize
		}
		if fsize != tree.Size {
			t.Fatalf("Frontier size mismatch")
		}

		incrementalFrontier.Add(λ[nPeers-1])
		if !reflect.DeepEqual(incrementalFrontier, f) {
			t.Fatalf("Frontier incremental mismatch at tree size %d", nPeers)
		}
	}
}
