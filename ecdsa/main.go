package main

import (
	"fmt"
	"math/big"
	"crypto/rand"
	"crypto/elliptic"
	"fvss"
	"mta"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	//"github.com/SSSaaS/sssa-golang"
	//"github.com/actuallyachraf/gomorph/gaillier"
)

const (
	shares = 4
	minimum = 3
	participation = 3
)

func main () {
	//Initialization
	message := "test message"
	messageHash := chainhash.DoubleHashB([]byte(message))

	var u []*big.Int = make([]*big.Int, shares)
	u[0], _ = big.NewInt(0).SetString("1", 10)
	u[1], _ = big.NewInt(0).SetString("2", 10)
	u[2], _ = big.NewInt(0).SetString("3", 10)
	u[3], _ = big.NewInt(0).SetString("15669280622064402590813018920111567599171487990495490501918129189672877078534", 10)

	var coordinate []*big.Int = make([]*big.Int, shares)
	coordinate[0], _ = big.NewInt(0).SetString("1", 10)
	coordinate[1], _ = big.NewInt(0).SetString("2", 10)
	coordinate[2], _ = big.NewInt(0).SetString("3", 10)
	coordinate[3], _ = big.NewInt(0).SetString("4", 10)
	combined_player := []int{0, 1, 2} //the num of int should equal participation

	var multiVss [][]string = make([][]string, shares)
	var xVss []string

	var w []*big.Int = make([]*big.Int, shares)

	var k []*big.Int = make([]*big.Int, participation)
	var gama []*big.Int = make([]*big.Int, participation)

	var alpha [][]*big.Int = make([][]*big.Int, participation)
	var beta [][]*big.Int = make([][]*big.Int, participation)
	var miu [][]*big.Int = make([][]*big.Int, participation)
	var v [][]*big.Int = make([][]*big.Int, participation)

	var delta []*big.Int = make([]*big.Int, participation)
	var sigma []*big.Int = make([]*big.Int, participation)

	var capitalGama [][]*big.Int = make([][]*big.Int, participation)
	
	curveX := big.NewInt(1)
	curveP, _ := btcec.PrivKeyFromBytes(btcec.S256(), curveX.Bytes())
	curve := curveP.ToECDSA().Curve
	prime := curve.Params().N


	//Feldman-VSS of every u[i]
	var maxLen = 0
	var strings []string = make([]string, shares)
	for i, _ := range u {
		strings[i] = u[i].String()
		multiVss[i], _ = fvss.CreateCertain(minimum, shares, strings[i], coordinate)
		//multiVss[i], _ = fvss.CreateCZ(minimum, shares, strings[i], coordinate)

		if maxLen < len(multiVss[i][0]) / 88 {
			maxLen = len(multiVss[i][0]) / 88
		}
	}


	//Add xi to get a Shamir's secret sharing of x
	xVss, _ = fvss.Add(multiVss, maxLen)


	//Map (t,n) share into a (t',t') one and calculate w
	w, _ = fvss.CalW(combined_player, xVss)


	//Calculate delta and sigma
	for i, _ := range k {
		k[i] = random()
		gama[i] = random()
		alpha[i] = make([]*big.Int, participation)
		beta[i] = make([]*big.Int, participation)
		miu[i] = make([]*big.Int, participation)
		v[i] = make([]*big.Int, participation)
		delta[i] = big.NewInt(0)
		sigma[i] = big.NewInt(0)
		capitalGama[i] = make([]*big.Int, 2)
	}

	for i, _ := range k {
		for j, _ := range k {
			alpha[i][j], beta[i][j] = mta.MTA(k[i], gama[j])
			miu[i][j], v[i][j] = mta.MTA(k[i], w[j])
		}
	}

	for i, _ := range k {
		for j, _ := range k {
			if i == j {
				tmp := big.NewInt(0).Mul(k[i], gama[i])
				delta[i] = delta[i].Add(delta[i], tmp)

				tmp = big.NewInt(0).Mul(k[i], w[i])
				sigma[i] = sigma[i].Add(sigma[i], tmp)
			} else {
				delta[i] = delta[i].Add(delta[i], alpha[i][j])
				delta[i] = delta[i].Add(delta[i], beta[j][i])

				sigma[i] = sigma[i].Add(sigma[i], miu[i][j])
				sigma[i] = sigma[i].Add(sigma[i], v[j][i])
			}
		}
	}


	//Verify
	ksum := big.NewInt(0)
	deltasum := big.NewInt(0)
	sigmasum := big.NewInt(0)

	pubX := big.NewInt(0)
	pubY := big.NewInt(0)

	for i, _ := range k {
		ksum = ksum.Add(ksum, k[i])
		deltasum = deltasum.Add(deltasum, delta[i])
		sigmasum = sigmasum.Add(sigmasum, sigma[i])

		_, wPub := btcec.PrivKeyFromBytes(btcec.S256(), w[i].Bytes())
		pubX, pubY = curve.Add(pubX, pubY, wPub.X, wPub.Y)

		_, gamaPub := btcec.PrivKeyFromBytes(btcec.S256(), gama[i].Bytes())
		capitalGama[i][0] = gamaPub.X
		capitalGama[i][1] = gamaPub.Y
	}

	ksum = ksum.Mod(ksum, prime)
	deltasum = deltasum.Mod(deltasum, prime)
	sigmasum = sigmasum.Mod(sigmasum, prime)

	signature, _ := sign(curve, ksum, deltasum, sigmasum, capitalGama, messageHash)

	verified := verify(curve, messageHash, pubX, pubY, signature.R, signature.S)

	fmt.Printf("Signature Verified? %v\n", verified)
}

func sign(curve elliptic.Curve, k *big.Int, delta *big.Int, sigma *big.Int, capitalGama [][]*big.Int, hash []byte) (*btcec.Signature, error) {
	N := btcec.S256().N
	halfOrder := big.NewInt(0).Rsh(N, 1)

	rX := big.NewInt(0)
	rY := big.NewInt(0)
	for i, _ := range capitalGama {
		rX, rY = curve.Add(rX, rY, capitalGama[i][0], capitalGama[i][1])
	}

	inv := big.NewInt(0).ModInverse(delta, N)
	r, _ := curve.ScalarMult(rX, rY, inv.Bytes())
	r.Mod(r, N)

	m := hashToInt(hash, curve)
	s := big.NewInt(0).Mul(m, k)
	added := big.NewInt(0).Mul(r, sigma)
	added = added.Mod(added, N)
	s.Add(s, added)
	s.Mod(s, N)

	if s.Cmp(halfOrder) == 1 {
		s.Sub(N, s)
	}
	if s.Sign() == 0 {
		return nil, nil
	}
	return &btcec.Signature{R: r, S: s}, nil
}

func verify(curve elliptic.Curve, hash []byte, pubX, pubY, r, s *big.Int) bool {
	N := curve.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	e := hashToInt(hash, curve)

	var w *big.Int
	w = big.NewInt(0).ModInverse(s, N)

	u1 := e.Mul(e, w)
	u1.Mod(u1, N)
	u2 := w.Mul(r, w)
	u2.Mod(u2, N)

	var x, y *big.Int
	x1, y1 := curve.ScalarBaseMult(u1.Bytes())
	x2, y2 := curve.ScalarMult(pubX, pubY, u2.Bytes())
	x, y = curve.Add(x1, y1, x2, y2)

	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

func random() *big.Int {
	curveX := big.NewInt(1)
	curveP, _ := btcec.PrivKeyFromBytes(btcec.S256(), curveX.Bytes())
	curve := curveP.ToECDSA().Curve
	prime := curve.Params().N

	result := big.NewInt(0).Set(prime)
	result = result.Sub(result, big.NewInt(1))
	result, _ = rand.Int(rand.Reader, result)
	return result
}

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}
