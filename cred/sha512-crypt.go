package cred

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"strconv"
)

type Sha512CryptCredManager struct{}

func NewSha512CryptCredManager() *Sha512CryptCredManager {
	cm := &Sha512CryptCredManager{}
	return cm
}

const Hash64Chars = "./0123456789" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"abcdefghijklmnopqrstuvwxyz"

// Hash64 is a variant of Base64 encoding.  It is commonly used with
// password hashing algorithms to encode the result of their checksum
// output.
//
// The algorithm operates on up to 3 bytes at a time, encoding the
// following 6-bit sequences into up to 4 hash64 ASCII bytes.
//
//  1. Bottom 6 bits of the first byte
//  2. Top 2 bits of the first byte, and bottom 4 bits of the second byte.
//  3. Top 4 bits of the second byte, and bottom 2 bits of the third byte.
//  4. Top 6 bits of the third byte.
//
// This encoding method does not emit padding bytes as Base64 does.
func Hash64(src []byte) (hash []byte) {
	if len(src) == 0 {
		return []byte{}
	}

	hashSize := (len(src) * 8) / 6
	if (len(src) % 6) != 0 {
		hashSize += 1
	}
	hash = make([]byte, hashSize)

	dst := hash
	for len(src) > 0 {
		switch len(src) {
		default:
			dst[0] = Hash64Chars[src[0]&0x3f]
			dst[1] = Hash64Chars[((src[0]>>6)|(src[1]<<2))&0x3f]
			dst[2] = Hash64Chars[((src[1]>>4)|(src[2]<<4))&0x3f]
			dst[3] = Hash64Chars[(src[2]>>2)&0x3f]
			src = src[3:]
			dst = dst[4:]
		case 2:
			dst[0] = Hash64Chars[src[0]&0x3f]
			dst[1] = Hash64Chars[((src[0]>>6)|(src[1]<<2))&0x3f]
			dst[2] = Hash64Chars[(src[1]>>4)&0x3f]
			src = src[2:]
			dst = dst[3:]
		case 1:
			dst[0] = Hash64Chars[src[0]&0x3f]
			dst[1] = Hash64Chars[(src[0]>>6)&0x3f]
			src = src[1:]
			dst = dst[2:]

		}
	}

	return
}

const (
	MagicPrefix   = "$6$"
	RandomSalt    = ""
	RoundsDefault = 5000
	RoundsMax     = 999999999
	RoundsMin     = 1000
	SaltLenMax    = 16
	SaltLenMin    = 1
)

// GenerateSalt creates a random salt parameter string with the random
// bytes being of the length provided, and the rounds parameter set as
// specified.
//
// If the length is greater than SaltLenMax, a string of that length
// will be returned instead. Similarly, if length is less than
// SaltLenMin, a string of that length will be returned instead.
//
// If rounds is equal to RoundsDefault, then the 'rounds=' part of the
// salt parameter string is elided.
func GenerateSalt(length, rounds int) string {
	if length > SaltLenMax {
		length = SaltLenMax
	} else if length < SaltLenMin {
		length = SaltLenMin
	}
	rlen := (length * 6 / 8)
	if (length*6)%8 != 0 {
		rlen += 1
	}
	if rounds < RoundsMin {
		rounds = RoundsMin
	} else if rounds > RoundsMax {
		rounds = RoundsMax
	}
	buf := make([]byte, rlen)
	rand.Read(buf)
	salt := Hash64(buf)
	if rounds == RoundsDefault {
		return fmt.Sprintf("%s%s", MagicPrefix, salt)
	}
	return fmt.Sprintf("%srounds=%d$%s", MagicPrefix, rounds, salt)
}

// Crypt takes key and salt strings and performs the SHA512-crypt
// hashing algorithm on them, returning a full hash string suitable
// for storage and later password verification.
//
// If the salt string is the value RandomSalt, a randomly-generated
// salt parameter string will be generated with a length of SaltLenMax
// and RoundsDefault number of rounds.
func Crypt(keystr, saltstr string) string {
	var key, salt []byte
	var rounds, keyLen, saltLen int
	var roundsdef bool = false

	key = []byte(keystr)
	keyLen = len(key)

	if saltstr == "" {
		saltstr = GenerateSalt(SaltLenMax, RoundsDefault)
	}
	saltbytes := []byte(saltstr)
	if !bytes.HasPrefix(saltbytes, []byte(MagicPrefix)) {
		return "invalid prefix"
	}

	salttoks := bytes.Split(saltbytes, []byte{'$'})
	numtoks := len(salttoks)

	if numtoks < 3 {
		return "invalid salt format"
	}

	if bytes.HasPrefix(salttoks[2], []byte("rounds=")) {
		roundsdef = true
		pr, err := strconv.ParseInt(string(salttoks[2][7:]), 10, 32)
		if err != nil {
			return "invalid rounds"
		}
		rounds = int(pr)
		if rounds < RoundsMin {
			rounds = RoundsMin
		} else if rounds > RoundsMax {
			rounds = RoundsMax
		}
		salt = salttoks[3]
	} else {
		rounds = RoundsDefault
		salt = salttoks[2]
	}

	if len(salt) > 16 {
		salt = salt[0:16]
	}
	saltLen = len(salt)

	B := sha512.New()
	B.Write(key)
	B.Write(salt)
	B.Write(key)
	Bsum := B.Sum(nil)

	A := sha512.New()
	A.Write(key)
	A.Write(salt)
	cnt := keyLen
	for ; cnt > 64; cnt -= 64 {
		A.Write(Bsum)
	}
	A.Write(Bsum[0:cnt])
	for cnt = keyLen; cnt > 0; cnt >>= 1 {
		if (cnt & 1) != 0 {
			A.Write(Bsum)
		} else {
			A.Write(key)
		}
	}
	Asum := A.Sum(nil)

	P := sha512.New()
	for cnt = 0; cnt < keyLen; cnt++ {
		P.Write(key)
	}
	Psum := P.Sum(nil)

	Pseq := make([]byte, 0, keyLen)
	for cnt = keyLen; cnt > 64; cnt -= 64 {
		Pseq = append(Pseq, Psum...)
	}
	Pseq = append(Pseq, Psum[0:cnt]...)

	S := sha512.New()
	for cnt = 0; cnt < (16 + int(Asum[0])); cnt++ {
		S.Write(salt)
	}
	Ssum := S.Sum(nil)

	Sseq := make([]byte, 0, saltLen)
	for cnt = saltLen; cnt > 64; cnt -= 64 {
		Sseq = append(Sseq, Ssum...)
	}
	Sseq = append(Sseq, Ssum[0:cnt]...)

	Csum := Asum
	for cnt = 0; cnt < rounds; cnt++ {
		C := sha512.New()

		if (cnt & 1) != 0 {
			C.Write(Pseq)
		} else {
			C.Write(Csum)
		}

		if (cnt % 3) != 0 {
			C.Write(Sseq)
		}

		if (cnt % 7) != 0 {
			C.Write(Pseq)
		}

		if (cnt & 1) != 0 {
			C.Write(Csum)
		} else {
			C.Write(Pseq)
		}

		Csum = C.Sum(nil)
	}

	buf := bytes.NewBuffer(make([]byte, 0, 123))
	buf.WriteString(MagicPrefix)
	if roundsdef {
		buf.WriteString(fmt.Sprintf("rounds=%d$", rounds))
	}
	buf.Write(salt)
	buf.WriteByte('$')
	buf.Write(Hash64([]byte{
		Csum[42], Csum[21], Csum[0],
		Csum[1], Csum[43], Csum[22],
		Csum[23], Csum[2], Csum[44],
		Csum[45], Csum[24], Csum[3],
		Csum[4], Csum[46], Csum[25],
		Csum[26], Csum[5], Csum[47],
		Csum[48], Csum[27], Csum[6],
		Csum[7], Csum[49], Csum[28],
		Csum[29], Csum[8], Csum[50],
		Csum[51], Csum[30], Csum[9],
		Csum[10], Csum[52], Csum[31],
		Csum[32], Csum[11], Csum[53],
		Csum[54], Csum[33], Csum[12],
		Csum[13], Csum[55], Csum[34],
		Csum[35], Csum[14], Csum[56],
		Csum[57], Csum[36], Csum[15],
		Csum[16], Csum[58], Csum[37],
		Csum[38], Csum[17], Csum[59],
		Csum[60], Csum[39], Csum[18],
		Csum[19], Csum[61], Csum[40],
		Csum[41], Csum[20], Csum[62],
		Csum[63],
	}))

	return buf.String()
}

// Verify hashes a key using the same salt parameters as the given
// hash string, and if the results match, it returns true.
func Verify(key, hash string) bool {
	nhash := Crypt(key, hash)
	if hash == nhash {
		return true
	}
	return false
}

func (cm *Sha512CryptCredManager) GetHashedPassword(password string, userSalt string, organizationSalt string) string {
	return Crypt(password, userSalt)
}

func (cm *Sha512CryptCredManager) IsPasswordCorrect(plainPwd string, hashedPwd string, userSalt string, organizationSalt string) bool {
	return Verify(plainPwd, hashedPwd)
}
