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
	CurveType asn1.Enumerated "tag:10"
	D *big.Int
}

func dumpPrivKey(priv ECDSAPriv) ([]byte, error){

	rbyte, err := asn1.Marshal(priv)
	if err != nil {
		return nil, err
	}
	
	return rbyte, nil
}

func importPrivKey(kb []byte)(*ECDSAPriv, error){
	
	var priv = ECDSAPriv{}
	_, err := asn1.Unmarshal(kb, &priv)
	
	if err != nil {
		return nil, err
	}
	
	return &priv, nil		
}

const(
	
	ECP256_FIPS186 = 1
	ECP256_SEC2k1 = 16
)


func DumpPrivKey(priv ECDSAPriv) (string, error){
	
	rb, err := dumpPrivKey(priv)
	if err != nil{
		return "ERROR", err
	}
	
	return base64.StdEncoding.EncodeToString(rb), nil
}

func PrivKeyfromString(kstr string) (*ECDSAPriv, error){
	
	data, err := base64.StdEncoding.DecodeString(kstr)
	if err != nil {
		return nil, err
	}
	
	return importPrivKey(data)	
}

func (k ECDSAPriv) apply() (*ecdsa.PrivateKey, error){
	
	var curve elliptic.Curve	
	
	if k.D == nil{
		return nil, errors.New(fmt.Sprintf("empty seed field"))	
	}
	
	switch(k.CurveType){
		case 1:
			curve = elliptic.P256()
		default:
			return nil, errors.New(fmt.Sprintf("%d is not a valid curve defination", k.CurveType))		
	}
	
	retx, rety := curve.ScalarBaseMult(k.D.Bytes())
	
	return &ecdsa.PrivateKey{  ecdsa.PublicKey{curve, retx, rety}, k.D}, nil
}



