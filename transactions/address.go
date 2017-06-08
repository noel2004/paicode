package transactions

import (
	"errors"
	"math/big"
	"encoding/asn1"
	"encoding/base64"
	"crypto/sha256"
	"golang.org/x/crypto/ripemd160"
)

func (pk *PublicKey) GetUserHash() ([]byte, error) {
	
	type StandardPk struct{
		X *big.Int
		Y *big.Int
	}
	
	stdpk := StandardPk{X: pk.X, Y: pk.Y}
	
	rawbytes, err := asn1.Marshal(stdpk)
	
	if err != nil{
		return nil, err
	}
	
	hash1pass := sha256.Sum256(rawbytes)
	if len(hash1pass) != sha256.Size{
		return nil, errors.New("Wrong sha256 hashing")
	}
	
	rmd160h := ripemd160.New();
	if nn, err := rmd160h.Write(hash1pass[:]); nn != len(hash1pass) || err != nil{
		return nil, errors.New("Wrong ripemd write")
	}
	
	hash2pass := rmd160h.Sum([]byte{})
	
	if len(hash2pass) != ripemd160.Size{
		return nil, errors.New("Wrong ripemd160 hashing")
	}
	
	return hash2pass, nil
}

const (
	AddressFullByteSize = 25
	AddressPartByteSize = 21
	AddressVerifyCodeSize = 4
)

func getVerifyCode(rb []byte) ([4]byte, error){
	
	hash1pass := sha256.Sum256(rawbytes)
	if len(hash1pass) != sha256.Size{
		return nil, errors.New("Wrong sha256 hashing 1pass")
	}	
	
	hash2pass := sha256.Sum256(hash1pass)
	if len(hash2pass) != sha256.Size{
		return nil, errors.New("Wrong sha256 hashing 2pass")
	}	
	
}

func (pk *PublicKey) GetUserId() string{
	
	fullbytes := make([]byte, uint8(pk.CurveType % 256))
	
	hashbytes, err := pk.GetUserHash()
	if err != nil{
		return ""
	}
	
	fullbytes = append(fullbytes, hashbytes)
	
	hash1pass := sha256.Sum256(rawbytes)
	if len(hash1pass) != sha256.Size{
		return nil, errors.New("Wrong sha256 hashing 1pass")
	}	
	
	hash2pass := sha256.Sum256(hash1pass)
	if len(hash2pass) != sha256.Size{
		return nil, errors.New("Wrong sha256 hashing 2pass")
	}	
	
	
	
	return base64.StdEncoding.EncodeToString(hashbytes)
}


	
	



