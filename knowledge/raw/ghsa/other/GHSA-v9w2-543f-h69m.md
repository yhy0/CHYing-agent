# Fabric vulnerable to crosslinking transaction attack

**GHSA**: GHSA-v9w2-543f-h69m | **CVE**: CVE-2023-46132 | **Severity**: high (CVSS 7.1)

**CWE**: CWE-362

**Affected Packages**:
- **github.com/hyperledger/fabric** (go): >= 1.0.0-alpha, < 2.2.14
- **github.com/hyperledger/fabric** (go): >= 2.3.0, < 2.5.5

## Description

# Short summary

Combining two molecules to one another, called "cross-linking" results in a molecule with a chemical formula that is composed of all atoms of the original two molecules. 

In Fabric, one can take a block of transactions and cross-link the transactions in a way that alters the way the peers parse the transactions. If a first peer receives a block `B` and a second peer receives a block identical to `B` but with the transactions being cross-linked, the second peer will parse transactions in a different way and thus its world state will deviate from the first peer. 

Orderers or peers cannot detect that a block has its transactions cross-linked, because there is a vulnerability in the way Fabric hashes the transactions of blocks. It simply and naively concatenates them, which is insecure and lets an adversary craft a "cross-linked block" (block with cross-linked transactions) which alters the way peers process transactions. 
For example, it is possible to select a transaction and manipulate a peer to completely avoid processing it, without changing the computed hash of the block.

Additional validations have been added in v2.2.14 and v2.5.5 to detect potential cross-linking issues before processing blocks.

## Impact
In V1 and V2, we only have a crash fault tolerant orderer and as such, the security model Fabric operates in is that the orderer is honest,
but peers may be malicious. As such, a peer that replicates a block from a malicious peer can have a state fork.

In V3 which we did not a release a GA yet (only a preview), we have a byzantine fault tolerant orderering service, so the security model that Fabric operates in such a case includes malicious orderers. If the orderer is malicious, it can cause state forks for peers, and can infect non-malicious orderers with cross-linked blocks.

# Long summary

In order to create a signature on a big chunk of data  such as a block, the data needs to be "compressed" first to the input size of the signature algorithm.

In Fabric's case, we use a hash function which compressed a Fabric block from arbitrary size to a 32 byte string.

In order to understand the problem we need to be more specific: The block structure has three parts to it: (1) Header, (2) Transactions, and (3) Metadata.

When hashing the block, the header and metadata are stitched together and then hashed, and this hash of the header and the metadata is what signed (it's a simplification but let's not get into details)

However, the transactions of the block are not part of the above hash. Instead, the header contains a hash, called the "Data hash" and despite the fact that in the comments it is said: "// The hash of the BlockData, by MerkleTree", actually it is far from being the case, and that is where our problem lies.

The problem is that the way the transactions are hashed gives an attacker some freedom in manipulating the data. 

To create the Data Hash, the transactions in the block are concatenated to one another, creating a big long byte array and then this big long byte array is hashed, and this is essentially the Data Hash.

The transactions in the block are a list of raw byte arrays, and when they are concatenated they look like this:

`|$$$$$$$$$$$$|*************|@@@@@@@@@@@@|%%%%%%%%%|`  (The vertical lines " | " represent how transactions are separated in a block.)

When the transactions are concatenated in order to be hashed, the payload that is hashed is: 
`$$$$$$$$$$$$*************@@@@@@@@@@@@%%%%%%%%%`

An adversary can't change the bytes of the concatenation, however what it can do, is to modify how transactions are encoded in the block:

For example, consider an adversary wants to manipulate a peer to skip the second transaction (******).

It can then create a block with the transactions as follows:

`|$$$$$$$$$$$$*************|@@@@@@@@@@@@|%%%%%%%%%| `

Notice that a block with the above transactions has the same concatenation of bytes as the original block, but the block has one less transaction - the first transaction is a concatenation of the first and second transactions in the original block.

When the peer receives this block, it looks at the first transaction and when it parses it, it completely ignores the ***** bytes, (we will see why soon), and so, an adversary can create a block with the same hash but different transactions and this would create a fork in the network.
 
I made a small PoC where I created a block with 2 transactions (by invoking two chaincodes at the same time) with a Raft orderer:

```
    [e][OrdererOrg.orderer] 2023-10-14 23:07:34.076 CEST 0079 INFO [orderer.consensus.etcdraft] propose -> Created block [10] with 2 transactions, there are 0 blocks in flight channel=testchannel node=1
```

But right after creating the block, I just modified only its transaction content (without modifying the block hash) and then the peers only detect a single transaction inside that block:
 
```
    [e][Org2.peer0] 2023-10-14 23:07:34.079 CEST 0099 INFO [kvledger] commit -> [testchannel] Committed block [10] with 1 transaction(s) in 0ms (state_validation=0ms block_and_pvtdata_commit=0ms state_commit=0ms) commitHash=[c5ecca818da9319af2f276dd01cd1337938f20c3535dd23f95a33933a114fe84]
```

The important takeaway from this experiment is that the peer does not detect any tempering was done to the block. If an attacker performs this attack, the network can be forked silently and no one will notice the network was forked until it's too late.

 

# Patches
Here is the patch I propose (the explanation is further below): 

```
diff --git a/internal/peer/gossip/mcs.go b/internal/peer/gossip/mcs.go
index b46df8b6a..9c3b5c8fd 100644
--- a/internal/peer/gossip/mcs.go
+++ b/internal/peer/gossip/mcs.go
@@ -150,6 +150,10 @@ func (s *MSPMessageCryptoService) VerifyBlock(chainID common.ChannelID, seqNum u
 		return fmt.Errorf("Block with id [%d] on channel [%s] does not have metadata. Block not valid.", block.Header.Number, chainID)
 	}
 
+	if err := protoutil.VerifyTransactionsAreWellFormed(block); err != nil {
+		return err
+	}
+
 	// - Verify that Header.DataHash is equal to the hash of block.Data
 	// This is to ensure that the header is consistent with the data carried by this block
 	if !bytes.Equal(protoutil.BlockDataHash(block.Data), block.Header.DataHash) {
diff --git a/orderer/common/cluster/util.go b/orderer/common/cluster/util.go
index e229bebfc..05b1bfaa9 100644
--- a/orderer/common/cluster/util.go
+++ b/orderer/common/cluster/util.go
@@ -260,6 +260,9 @@ func VerifyBlockHash(indexInBuffer int, blockBuff []*common.Block) error {
 	if block.Header == nil {
 		return errors.New("missing block header")
 	}
+	if err := protoutil.VerifyTransactionsAreWellFormed(block); err != nil {
+		return err
+	}
 	seq := block.Header.Number
 	dataHash := protoutil.BlockDataHash(block.Data)
 	// Verify data hash matches the hash in the header
diff --git a/orderer/consensus/smartbft/verifier.go b/orderer/consensus/smartbft/verifier.go
index 2b9fdfc4c..f232a1eae 100644
--- a/orderer/consensus/smartbft/verifier.go
+++ b/orderer/consensus/smartbft/verifier.go
@@ -237,6 +237,10 @@ func verifyHashChain(block *cb.Block, prevHeaderHash string) error {
 		return errors.Errorf("previous header hash is %s but expected %s", thisHdrHashOfPrevHdr, prevHeaderHash)
 	}
 
+	if err := protoutil.VerifyTransactionsAreWellFormed(block); err != nil {
+		return err
+	}
+
 	dataHash := hex.EncodeToString(block.Header.DataHash)
 	actualHashOfData := hex.EncodeToString(protoutil.BlockDataHash(block.Data))
 	if dataHash != actualHashOfData {
diff --git a/protoutil/blockutils.go b/protoutil/blockutils.go
index 8527869e4..fca3c386f 100644
--- a/protoutil/blockutils.go
+++ b/protoutil/blockutils.go
@@ -10,6 +10,7 @@ import (
 	"bytes"
 	"crypto/sha256"
 	"encoding/asn1"
+	"encoding/base64"
 	"fmt"
 	"math/big"
 
@@ -298,3 +299,35 @@ func searchConsenterIdentityByID(consenters []*cb.Consenter, identifier uint32)
 	}
 	return nil
 }
+
+func VerifyTransactionsAreWellFormed(block *cb.Block) error {
+	if block == nil || block.Data == nil || len(block.Data.Data) == 0 {
+		return nil
+	}
+
+	for i, rawTx := range block.Data.Data {
+		env := &cb.Envelope{}
+		if err := proto.Unmarshal(rawTx, env); err != nil {
+			return fmt.Errorf("transaction %d is invalid: %v", i, err)
+		}
+
+		if len(env.Payload) == 0 {
+			return fmt.Errorf("transaction %d has no payload", i)
+		}
+
+		if len(env.Signature) == 0 {
+			return fmt.Errorf("transaction %d has no signature", i)
+		}
+
+		expected := MarshalOrPanic(env)
+		if len(expected) < len(rawTx) {
+			return fmt.Errorf("transaction %d has %d trailing bytes", i, len(rawTx)-len(expected))
+		}
+		if !bytes.Equal(expected, rawTx) {
+			return fmt.Errorf("transaction %d (%s) does not match its raw form (%s)", i,
+				base64.StdEncoding.EncodeToString(expected), base64.StdEncoding.EncodeToString(rawTx))
+		}
+	}
+
+	return nil
+}
diff --git a/protoutil/blockutils_test.go b/protoutil/blockutils_test.go
index b2159da9f..2871483f1 100644
--- a/protoutil/blockutils_test.go
+++ b/protoutil/blockutils_test.go
@@ -489,3 +489,109 @@ func TestBlockSignatureVerifierByCreator(t *testing.T) {
 	require.Len(t, signatureSet, 1)
 	require.Equal(t, []byte("creator1"), signatureSet[0].Identity)
 }
+
+func TestVerifyTransactionsAreWellFormed(t *testing.T) {
+	originalBlock := &cb.Block{
+		Data: &cb.BlockData{
+			Data: [][]byte{
+				marshalOrPanic(&cb.Envelope{
+					Payload:   []byte{1, 2, 3},
+					Signature: []byte{4, 5, 6},
+				}),
+				marshalOrPanic(&cb.Envelope{
+					Payload:   []byte{7, 8, 9},
+					Signature: []byte{10, 11, 12},
+				}),
+			},
+		},
+	}
+
+	forgedBlock := proto.Clone(originalBlock).(*cb.Block)
+	tmp := make([]byte, len(forgedBlock.Data.Data[0])+len(forgedBlock.Data.Data[1]))
+	copy(tmp, forgedBlock.Data.Data[0])
+	copy(tmp[len(forgedBlock.Data.Data[0]):], forgedBlock.Data.Data[1])
+	forgedBlock.Data.Data = [][]byte{tmp} // Replace transactions {0,1} with transaction {0 || 1}
+
+	for _, tst := range []struct {
+		name          string
+		expectedError string
+		block         *cb.Block
+	}{
+		{
+			name: "empty block",
+		},
+		{
+			name:  "no block data",
+			block: &cb.Block{},
+		},
+		{
+			name:  "no transactions",
+			block: &cb.Block{Data: &cb.BlockData{}},
+		},
+		{
+			name: "single transaction",
+			block: &cb.Block{Data: &cb.BlockData{Data: [][]byte{marshalOrPanic(&cb.Envelope{
+				Payload:   []byte{1, 2, 3},
+				Signature: []byte{4, 5, 6},
+			})}}},
+		},
+		{
+			name:  "good block",
+			block: originalBlock,
+		},
+		{
+			name:          "forged block",
+			block:         forgedBlock,
+			expectedError: "transaction 0 has 10 trailing bytes",
+		},
+		{
+			name:          "no signature",
+			expectedError: "transaction 0 has no signature",
+			block: &cb.Block{
+				Data: &cb.BlockData{
+					Data: [][]byte{
+						marshalOrPanic(&cb.Envelope{
+							Payload: []byte{1, 2, 3},
+						}),
+					},
+				},
+			},
+		},
+		{
+			name:          "no payload",
+			expectedError: "transaction 0 has no payload",
+			block: &cb.Block{
+				Data: &cb.BlockData{
+					Data: [][]byte{
+						marshalOrPanic(&cb.Envelope{
+							Signature: []byte{4, 5, 6},
+						}),
+					},
+				},
+			},
+		},
+		{
+			name:          "transaction invalid",
+			expectedError: "transaction 0 is invalid: proto: cannot parse invalid wire-format data",
+			block: &cb.Block{
+				Data: &cb.BlockData{
+					Data: [][]byte{
+						marshalOrPanic(&cb.Envelope{
+							Payload:   []byte{1, 2, 3},
+							Signature: []byte{4, 5, 6},
+						})[9:],
+					},
+				},
+			},
+		},
+	} {
+		t.Run(tst.name, func(t *testing.T) {
+			err := protoutil.VerifyTransactionsAreWellFormed(tst.block)
+			if tst.expectedError == "" {
+				require.NoError(t, err)
+			} else {
+				require.EqualError(t, err, tst.expectedError)
+			}
+		})
+	}
+}

```

The idea is as follows:

When we validate that the block's transactions match the hash in the header, we not only hash the transactions are earlier, 

but also ensure that if the transactions in the block are encoded into bytes, they re-create the exact split in the original block: `|$$$$$$$$$$$$|***********|@@@@@@@@@|%%%%%%%%%%%|`

More specifically, each transaction in the block is parsed and then re-encoded to bytes, and we check that the original encoding of a transaction is as the second encoding after parsing the original bytes of the transaction.

This fix keeps the legacy way of hashing transactions to create the block data hash, but also aims to check if some manipulation was done.

 
To understand why the fix works, we need to understand how protobuf, the wire protocol that Fabric uses to encode transactions (and almost anything it sends over the wire or writes to disk) encodes a transaction.

A transaction is a protobuf message with two fields of bytes: (1) Payload and (2) Signature.

When encoding a field of bytes, protobuf first writes a tag for the field (a byte) and then writes the length of the field in variable-length encoding, and then the bytes themselves.

For example, to encode a transaction, protobuf writes 10 (the tag for payload), then two bytes for the length of the payload, then the payload, and then 18, the tag for the signature, and then a single byte for the length of the signature, and finally the signature.

Now, we can understand a proof sketch of why my solution works:

Assume in contradiction that an adversary takes a block of transactions and changes the split of the concatenation in a way that changes the transactions for a peer:

From `|$$$$$$$$$$$$|************|@@@@@@@@@@@|...|%%%%%%%|` to (for example): From `|$$$$$$$$$$$$************|@@@@@@@@@@@|...|%%%%%%%|` 

Since this split is not identical to the original split, there exists at least one transaction index of different size between the two splits. Let's look at the first transaction that is of different size.

For example, for the split:

`|$$$$$$$$$$$$|************|@@@@@@@@@@@|...|%%%%%%%|`  we have two options:

1.  The first transaction of different size is smaller in the new split:  `|$$$$$$$$$$$$|*****|*******|@@@@@@@@@@@|...|%%%%%%%|`  In such a case, it must contain both a payload and a signature, so it needs two fields (we can say we will return an error if one of the two is missing). If the protobuf parser detects it lacks bytes to parse a payload, it will fail with an error. Else, it has enough bytes to parse the payload, and then the signature is parsed. If the signature field is too short then we also error similarly.

2. The first transaction of different size is bigger in the new split: `|$$$$$$$$$$$$|************@@@@|@@@@@@@|...|%%%%%%%|` 
In that case, once this transaction is parsed, the extra bytes are skipped, so encoding the transaction to bytes yields a shorter byte array, and we detect a tempering.


