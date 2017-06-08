package transactions

import (
	"fmt"
	"errors"
	_ "crypto/ecdsa"
	"math/big"
	"encoding/base64"
	
	"github.com/golang/protobuf/proto"
	pb "gamecenter.mobi/paicode/protos"
	_ "gamecenter.mobi/paicode/crypto"
)

type FundTx struct{
	Nounce []byte
	From string
	To   string
	Amount uint
	Invoked bool
	InvokedCode uint
	signX, signY *big.Int
}

func (f *FundTx) fill(v interface{}) error{
	switch data := v.(type){
		case *pb.UserTxHeader:
		f.From = data.FundId
		f.Nounce = data.Nounce
		case *pb.Fund:
		case *pb.Signature:
		case *pb.Funddata:
	}
	
	return nil
}

func ParseFundTransaction(args []string) (*FundTx, error){
	
	if len(args) < 3 {
		return nil, errors.New(fmt.Sprint("Not enough args, expect at least 3 but only", len(args)))
	}
	
	ftx := new(FundTx)
	
	for i, arg := range args{
		data, err := base64.StdEncoding.DecodeString(arg)
		
		if err != nil{
			return nil, errors.New(fmt.Sprint("base64 decode arg", i, "fail:", err))
		}
		
		var vif proto.Message
		switch i {
			case 0:vif = &pb.UserTxHeader{}
			case 1:vif = &pb.Fund{}
			case 2:vif = &pb.Signature{}
			case 3:vif = &pb.Funddata{}
			default:
				
		}
		
		err = proto.Unmarshal(data, vif)
		if err != nil{
			return nil, errors.New(fmt.Sprint("protobuf decode fail", err))
		}
		
		err = ftx.fill(vif)
		if err != nil{
			return nil, errors.New(fmt.Sprint("filling transaction fail", err))
		}		
	}
	
	
	
	return nil, nil
}


