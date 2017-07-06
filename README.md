treekeys
========

An attempt to implement the [tree-based group keying
scheme](https://eprint.iacr.org/2017/666.pdf) described by Cohn-Gordon, et al.

## Quickstart 

```
> go get github.com/bifurcation/treekeys
> go test github.com/bifurcation/treekeys -run Performance -v
```

## Performance 

On my MacBook Pro:

```
  Nodes   Setup  AckSetup  Update  AckUpdate
============================================
      3       1         0       0          0
      7       4         0       0          0
    127     115         0       0          0
   1023    1067         0       1          0
  32767   41825         6       7          8
 131071  183468        41      20         19

```
