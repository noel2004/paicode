package crypto

import (
	"fmt"
	"errors"
	"encoding/asn1"
	"encoding/base64"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"	

)

type ECDSAPriv struct {
	curveType asn1.Enumerated
	D *big.Int
}

func DumpPrivKey(priv ECDSAPriv) (string, error){
	
	rbyte, err := asn1.Marshal(priv)
	if err != nil {
		return "", err
	}
	
	return base64.StdEncoding.EncodeToString(rbyte), nil
	
}

func PrivKeyfromString(kstr string) (*ECDSAPriv, error){
	
	data, err := base64.StdEncoding.DecodeString(kstr)
	if err != nil {
		return nil, err
	}
	
	var priv ECDSAPriv
	_, err = asn1.Unmarshal(data, priv)
	
	if err != nil {
		return nil, err
	}
	
	return &priv, nil		
}

func (k ECDSAPriv) apply() (*ecdsa.PrivateKey, error){
	
	var curve elliptic.Curve	
	
	switch(k.curveType){
		case 1:
			curve = elliptic.P256()
		default:
			return nil, errors.New(fmt.Sprintf("%d is not a valid curve defination", k.curveType))		
	}
	
	retx, rety := curve.ScalarBaseMult(k.D.Bytes())
	
	return &ecdsa.PrivateKey{  ecdsa.PublicKey{curve, retx, rety}, k.D}, nil
}



