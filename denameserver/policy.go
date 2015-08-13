// Copyright 2014 The Dename Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package server

import (
	"fmt"
	. "github.com/andres-erbsen/dename/protocol"
	"github.com/gogo/protobuf/proto"
)

type errWontExpire error
type errExpired error
type errProfileVersion error

func resolve(merklemap *MerkleMap, name []byte) (
	profile *Profile, profileData []byte, proof []*ClientReply_MerklemapNode) {
	profileData, proof = merklemap.Lookup(name)
	if profileData == nil {
		return
	}
	profile = new(Profile)
	MustUnmarshal(profileData, profile)
	return
}

func validateOperation(merklemap *MerkleMap, signedOp *SignedProfileOperation, time uint64) (
	name, profileData []byte, err error) {
	op := new(SignedProfileOperation_ProfileOperationT)
	if err = proto.Unmarshal(signedOp.ProfileOperation, op); err != nil {
		return
	}
	newProfile := new(Profile)
	if err = proto.Unmarshal(op.NewProfile, newProfile); err != nil {
		return
	}
	if *newProfile.ExpirationTime <= time {
		err = errExpired(fmt.Errorf("validateOperation: profile already expired: %d <= %d", newProfile.ExpirationTime, time))
		return
	}
	if *newProfile.ExpirationTime > time+MAX_VALIDITY_PERIOD {
		err = errWontExpire(fmt.Errorf("validateOperation: profile valid for too long: %d > %d", newProfile.ExpirationTime, time+MAX_VALIDITY_PERIOD))
		return
	}
	err = newProfile.SignatureKey.VerifySignature("ModifyProfileNew",
		signedOp.ProfileOperation, signedOp.NewProfileSignature)
	if err != nil {
		return op.Name, nil, fmt.Errorf("validateOperation: new signature: %s", err)
	}
	oldProfile, _, _ := resolve(merklemap, op.Name)
	if oldProfile == nil || *oldProfile.ExpirationTime < time {
		if newProfile.GetVersion() != 0 {
			return op.Name, nil, errProfileVersion(fmt.Errorf("the version of a new profile must be 0 (got %d)", newProfile.GetVersion()))
		}
		return op.Name, op.NewProfile, nil
	}
	if err = oldProfile.SignatureKey.VerifySignature("ModifyProfileOld",
		signedOp.ProfileOperation, signedOp.OldProfileSignature); err != nil {
		return op.Name, nil, fmt.Errorf("validateOperation: old signature: %s", err)
	}
	if newProfile.GetVersion() <= oldProfile.GetVersion() {
		return op.Name, nil, errProfileVersion(fmt.Errorf("profile version must increase (got %d <= %d)", newProfile.GetVersion(), oldProfile.GetVersion()))
	}
	return op.Name, op.NewProfile, err
}
