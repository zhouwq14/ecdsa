package fvss

import (
	"fmt"
	"encoding/hex"
	"bytes"
	"strings"
	"errors"
	"math/big"
	"github.com/btcsuite/btcd/btcec"
)

var (
	ErrCannotRequireMoreShares = errors.New("cannot require more shares then existing")
	ErrOneOfTheSharesIsInvalid = errors.New("one of the shares is invalid")
)

func CreateCertain(minimum int, shares int, raw string, coordinate []*big.Int) ([]string, error) {
	if minimum > shares {
		return []string{""}, ErrCannotRequireMoreShares
	}

	var secret []*big.Int = splitByteToInt([]byte(raw))
	for _, v := range secret {
		v.SetString(string(BigIntToByte(v)), 10)
	}

	var numbers []*big.Int = make([]*big.Int, 0)
	numbers = append(numbers, big.NewInt(0))

	var polynomial [][]*big.Int = make([][]*big.Int, len(secret))
	for i := range polynomial {
		polynomial[i] = make([]*big.Int, minimum)
		polynomial[i][0] = secret[i]

		for j := range polynomial[i][1:] {
			number := random()
			for inNumbers(numbers, number) {
				number = random()
			}
			numbers = append(numbers, number)

			polynomial[i][j+1] = number
		}
	}

	var secrets [][][]*big.Int = make([][][]*big.Int, shares)
	var result []string = make([]string, shares)

	for i := range secrets {
		secrets[i] = make([][]*big.Int, len(secret))
		for j := range secrets[i] {
			secrets[i][j] = make([]*big.Int, 2)

			secrets[i][j][0] = coordinate[i]
			secrets[i][j][1] = evaluatePolynomial(polynomial[j], coordinate[i])

			result[i] += toBase64(secrets[i][j][0])
			result[i] += toBase64(secrets[i][j][1])
		}
	}

	return result, nil
}

func Combine(shares []string) (string, error) {
	var secrets [][][]*big.Int = make([][][]*big.Int, len(shares))

	curveX := big.NewInt(1)
	curveP, _ := btcec.PrivKeyFromBytes(btcec.S256(), curveX.Bytes())
	curve := curveP.ToECDSA().Curve
	prime := curve.Params().N

	for i := range shares {
		if IsValidShare(shares[i]) == false {
			return "", ErrOneOfTheSharesIsInvalid
		}

		share := shares[i]
		count := len(share) / 88
		secrets[i] = make([][]*big.Int, count)

		for j := range secrets[i] {
			cshare := share[j*88 : (j+1)*88]
			secrets[i][j] = make([]*big.Int, 2)
			secrets[i][j][0] = fromBase64(cshare[0:44])
			secrets[i][j][1] = fromBase64(cshare[44:])
		}
	}

	var secret []*big.Int = make([]*big.Int, len(secrets[0]))
	for j := range secret {
		secret[j] = big.NewInt(0)
		for i := range secrets {
			origin := secrets[i][j][0]
			originy := secrets[i][j][1]
			numerator := big.NewInt(1)
			denominator := big.NewInt(1)
			for k := range secrets {
				if k != i {
					current := secrets[k][j][0]
					negative := big.NewInt(0)
					negative = negative.Mul(current, big.NewInt(-1))
					added := big.NewInt(0)
					added = added.Sub(origin, current)

					numerator = numerator.Mul(numerator, negative)
					numerator = numerator.Mod(numerator, prime)

					denominator = denominator.Mul(denominator, added)
					denominator = denominator.Mod(denominator, prime)
				}
			}

			working := big.NewInt(0).Set(originy)
			working = working.Mul(working, numerator)
			working = working.Mul(working, modInverse(denominator))

			secret[j] = secret[j].Add(secret[j], working)
			secret[j] = secret[j].Mod(secret[j], prime)
		}
	}

	//new combine
	var result = ""
	for _, v := range secret {
		result += v.String()
	}

	return result, nil
}

func Add(str [][]string, maxLen int) ([]string, error) {
	var result []string = make([]string, len(str))
	curveX := big.NewInt(1)
	curveP, _ := btcec.PrivKeyFromBytes(btcec.S256(), curveX.Bytes())
	curve := curveP.ToECDSA().Curve
	prime := curve.Params().N

	for i := range str {
		for j := range str {
			if IsValidShare(str[i][j]) == false {
				return result, ErrOneOfTheSharesIsInvalid
			}
		}
	}

	for j := 0; j < len(str); j++ {
		for k := 0; k < maxLen; k++ {
			var sum *big.Int
			sum = big.NewInt(0)

			for i := 0; i < len(str); i++ {
				count := len(str[i][j]) / 88
				if k >= (maxLen-count) {
					tmp := k + count - maxLen

					var added *big.Int
					added = big.NewInt(0).Set(fromBase64(str[i][j][tmp*88+44 : (tmp+1)*88]))
					added.Mod(added, prime)
					sum.Add(sum, added)
					sum.Mod(sum, prime)
				}
			}
			sum.Mod(sum, prime)
			result[j] = result[j] + str[0][j][0:44] + toBase64(sum)
		}
	}

	return result, nil
}

func CalW(player []int, shares []string) ([]*big.Int, error) {
	var secrets [][][]*big.Int = make([][][]*big.Int, len(shares))
	var coordinates [][]*big.Int = make([][]*big.Int, len(shares))
	var result []*big.Int = make([]*big.Int, len(player))
	curveX := big.NewInt(1)
	curveP, _ := btcec.PrivKeyFromBytes(btcec.S256(), curveX.Bytes())
	curve := curveP.ToECDSA().Curve
	prime := curve.Params().N

	for i := range shares {
		if IsValidShare(shares[i]) == false {
			return result, ErrOneOfTheSharesIsInvalid
		}

		share := shares[i]
		count := len(share) / 88
		secrets[i] = make([][]*big.Int, count)
		coordinates[i] = make([]*big.Int, 2)
		var str_tmp = ""

		for j := range secrets[i] {
			cshare := share[j*88 : (j+1)*88]
			secrets[i][j] = make([]*big.Int, 2)
			secrets[i][j][0] = fromBase64(cshare[0:44])
			secrets[i][j][1] = fromBase64(cshare[44:])
			coordinates[i][0] = big.NewInt(0).Set(secrets[i][j][0])
			str_tmp += secrets[i][j][1].String()
		}
		coordinates[i][1], _ = big.NewInt(0).SetString(str_tmp, 10)
		coordinates[i][1].Mod(coordinates[i][1], prime)
	}

	for i := range player {
		result[i] = big.NewInt(0).Set(coordinates[i][1])
		numerator := big.NewInt(1)
		denominator := big.NewInt(1)
		var num_tmp *big.Int
		for j := range player {
			if j!=i {
				num_tmp = big.NewInt(0).Set(coordinates[j][0])
				num_tmp = num_tmp.Mod(num_tmp, prime)
				num_tmp = num_tmp.Sub(big.NewInt(0), num_tmp)
				num_tmp = num_tmp.Mod(num_tmp, prime)

				numerator = numerator.Mul(numerator, num_tmp)
				numerator = numerator.Mod(numerator, prime)

				num_tmp = big.NewInt(0).Set(coordinates[i][0])
				num_tmp = num_tmp.Mod(num_tmp, prime)
				num_tmp = num_tmp.Sub(num_tmp,coordinates[j][0])
				num_tmp = num_tmp.Mod(num_tmp, prime)

				denominator = denominator.Mul(denominator, num_tmp)
				denominator = denominator.Mod(denominator, prime)
			}
		}
		result[i] = result[i].Mul(result[i], numerator)
		result[i] = result[i].Mod(result[i], prime)
		result[i] = result[i].Mul(result[i], modInverse(denominator))
		result[i] = result[i].Mod(result[i], prime)
	}

	return result, nil
}

func IsValidShare(candidate string) bool { //same as before
	curveX := big.NewInt(1)
	curveP, _ := btcec.PrivKeyFromBytes(btcec.S256(), curveX.Bytes())
	curve := curveP.ToECDSA().Curve
	prime := curve.Params().N

	if len(candidate)%88 != 0 {
		return false
	}

	count := len(candidate) / 44
	for j := 0; j < count; j++ {
		part := candidate[j*44 : (j+1)*44]
		decode := fromBase64(part)
		if decode.Cmp(big.NewInt(0)) == -1 || decode.Cmp(prime) == 1 {
			return false
		}
	}

	return true
}

func BigIntToByte(secret *big.Int) []byte { //func beginning with lowercase letter can't be exported
	var hex_data = ""
	tmp := fmt.Sprintf("%x", secret)
	hex_data += strings.Join([]string{strings.Repeat("0", (64 - len(tmp))), tmp}, "")

	result, _ := hex.DecodeString(hex_data)
	result = bytes.TrimRight(result, "\x00")
	return result
}





/*func byteToBigInt(secret []byte) *big.Int {
	hex_data := hex.EncodeToString(secret)

	var result *big.Int

	if 64 < len(hex_data) {
		result, _ = big.NewInt(0).SetString(hex_data[0:64], 16)
	} else {
		data := strings.Join([]string{hex_data[0:], strings.Repeat("0", 64-len(hex_data))}, "")
		result, _ = big.NewInt(0).SetString(data, 16)
	}

	return result
}*/

func CreateCZ(minimum int, shares int, raw string, coordinate []*big.Int) ([]string, error) { //zero coordinates for test
	if minimum > shares {
		return []string{""}, ErrCannotRequireMoreShares
	}

	var secret []*big.Int = splitByteToInt([]byte(raw))
	for _, v := range secret {
		v.SetString(string(BigIntToByte(v)), 10)
	}

	var polynomial [][]*big.Int = make([][]*big.Int, len(secret))
	for i := range polynomial {
		polynomial[i] = make([]*big.Int, minimum)
		polynomial[i][0] = secret[i]

		for j := range polynomial[i][1:] {
			polynomial[i][j+1] = big.NewInt(0)
		}
	}

	var secrets [][][]*big.Int = make([][][]*big.Int, shares)
	var result []string = make([]string, shares)

	for i := range secrets {
		secrets[i] = make([][]*big.Int, len(secret))
		for j := range secrets[i] {
			secrets[i][j] = make([]*big.Int, 2)

			secrets[i][j][0] = coordinate[i]
			secrets[i][j][1] = evaluatePolynomial(polynomial[j], coordinate[i])

			result[i] += toBase64(secrets[i][j][0])
			result[i] += toBase64(secrets[i][j][1])
		}
	}

	return result, nil
}
