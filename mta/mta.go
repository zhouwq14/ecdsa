package mta

import (
	"math/big"
	"crypto/rand"
	"github.com/btcsuite/btcd/btcec"
	"github.com/actuallyachraf/gomorph/gaillier"
)

func MTA (a *big.Int, b *big.Int) (*big.Int, *big.Int) {
	curveX := big.NewInt(1)
	curveP, _ := btcec.PrivKeyFromBytes(btcec.S256(), curveX.Bytes())
	curve := curveP.ToECDSA().Curve
	prime := curve.Params().N

	pub, priv, _ := gaillier.GenerateKeyPair(rand.Reader, 1024)
	beta := randomBeta(pub.N)
	beta.Mod(beta, prime)

	Ca, _ := gaillier.Encrypt(pub, a.Bytes())
	Cbeta, _ := gaillier.Encrypt(pub, beta.Bytes())

	res := gaillier.Mul(pub, Ca, b.Bytes())
	res = gaillier.Add(pub, Cbeta, res)

	alphaBytes, _ := gaillier.Decrypt(priv, res)
	alpha := big.NewInt(0).SetBytes(alphaBytes)

	alpha = alpha.Mod(alpha, prime)
	beta = beta.Mod(big.NewInt(0).Sub(big.NewInt(0), beta), prime)

	return alpha, beta
}

func randomBeta(N *big.Int) *big.Int {
	curveX := big.NewInt(1)
	curveP, _ := btcec.PrivKeyFromBytes(btcec.S256(), curveX.Bytes())
	curve := curveP.ToECDSA().Curve
	prime := curve.Params().N

	result := big.NewInt(0).Set(N)
	minus := big.NewInt(1)

	minus = minus.Mul(minus, prime)
	minus = minus.Mul(minus, prime)

	result = result.Sub(result, minus)
	result = result.Sub(result, big.NewInt(1))
	result, _ = rand.Int(rand.Reader, result)

	return result
}
