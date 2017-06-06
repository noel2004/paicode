
package crypto

import (
	"testing"
	"crypto/rand"
	"crypto/ecdsa"
	"crypto/elliptic"	
)

func TestApply_Privkey(t *testing.T){
	
	prvkeystd, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil{
		t.Skip("Skip for ecdsa lib fail:", err)
	}
	
	var prvkeyt = ECDSAPriv{1, prvkeystd.D}
	prvkeytapp, err := prvkeyt.apply()
	
	if err != nil{
		t.Fatal(err)
	}
	
	if prvkeytapp.X.Cmp(prvkeystd.X) != 0 || prvkeytapp.Y.Cmp(prvkeystd.Y) != 0{
		t.Fatal("Unmatch public key:", prvkeytapp.X.Text(16), prvkeystd.X.Text(16), 
			prvkeytapp.Y.Text(16), prvkeystd.Y.Text(16))
	}
}
