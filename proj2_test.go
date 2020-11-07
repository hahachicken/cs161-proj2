package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func cnct(s1 []byte, s2 []byte) []byte {
	var re []byte = s1
	for i := 0; i < len(s2); i++ {
		re = append(re, s2[i])
	}
	return re
}

func Test_InitUser_0(t *testing.T) {
	clear()
	t.Log("InitUser(): Postive test")

	_, err := InitUser("alice", "password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user; ", err)
		return
	}
}

func Test_InitUser_1(t *testing.T) {
	clear()
	t.Log("InitUser(): duplicate username")

	_, err := InitUser("alice", "pass")
	_, err = InitUser("alice", "word")
	if err == nil {
		t.Error("successed to initialize user (should failed)")
		return
	}
}

func Test_GetUser_0(t *testing.T) {
	clear()
	t.Log("GetUser(): positive test")

	old, err := InitUser("alice", "password")
	if err != nil {
		t.Error(err)
		return
	}

	new, err := GetUser("alice", "password")
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(old, new) {
		t.Error("GetUser not the same with the init user")
		return
	}
}

func Test_GetUser_1(t *testing.T) {
	clear()
	t.Log("GetUser(): wrong password")

	_, err := InitUser("alice", "password")
	if err != nil {
		t.Error(err)
		return
	}

	_, err = GetUser("alice", "PassWord")
	if err == nil {
		t.Error("get user success(should failed); ", err)
		return
	}
}

func Test_GetUser_2(t *testing.T) {
	clear()
	t.Log("GetUser(): cleared Datastore")

	_, err := InitUser("alice", "password")
	if err != nil {
		t.Error(err)
		return
	}

	clear()
	_, err = GetUser("alice", "Password")
	if err == nil {
		t.Error("get user success(should failed); ", err)
		return
	}
}

func Test_GetUser_3(t *testing.T) {
	clear()
	t.Log("GetUser(): modified Datastore")

	_, err := InitUser("alice", "password")
	if err != nil {
		t.Error(err)
		return
	}
	{
		Addr, _ := uuid.FromBytes(userlib.Argon2Key([]byte("alice"), []byte("password"), 16))
		userlib.DatastoreSet(Addr, userlib.RandomBytes(int(userlib.RandomBytes(1)[0])))
	}

	_, err = GetUser("alice", "password")
	if err == nil {
		t.Error("get user success(should failed); ", err)
		return
	}
}

func Test_GetUser_4(t *testing.T) {
	clear()
	t.Log("GetUser(): double instance")

	A1, err := InitUser("alice", "password")
	if err != nil {
		t.Error(err)
		return
	}

	A2, err := GetUser("alice", "password")
	if err != nil {
		t.Error(err)
		return
	}

	data := []byte{0, 1}
	A1.StoreFile("file", data)
	dataRE, err := A2.LoadFile("file")
	if err != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(data, dataRE) {
		t.Error("double user behaver incosistant")
	}

	data = []byte{0, 1}
	A2.StoreFile("file", data)
	dataRE, err = A1.LoadFile("file")
	if err != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(data, dataRE) {
		t.Error("double user behaver incosistant")
	}

	data = cnct(data, []byte{2, 3})
	A2.AppendFile("file", []byte{2, 3})
	dataRE, err = A1.LoadFile("file")
	if err != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(data, dataRE) {
		t.Error("double user behaver incosistant")
	}

	data = cnct(data, []byte{4, 5})
	A1.AppendFile("file", []byte{4, 5})
	dataRE, err = A2.LoadFile("file")
	if err != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(data, dataRE) {
		t.Error("double user behaver incosistant")
	}
}

func Test_StoreFile_0(t *testing.T) {
	clear()
	t.Log("StoreFile(): new file")

	u, _ := InitUser("alice", "password")

	data := []byte("This is a test")
	u.StoreFile("file", data)

	dataRE1, err := u.LoadFile("file")
	if err != nil {
		t.Error(err)
		return
	}
	dataRE2, err := u.LoadFile("file")
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(data, dataRE1) || !reflect.DeepEqual(data, dataRE2) {
		t.Error("Downloaded file is not the same", data, dataRE1, dataRE2)
		return
	}
}

func Test_StoreFile_1(t *testing.T) {
	clear()
	t.Log("StoreFile(): exist file")

	u, _ := InitUser("alice", "password")

	data := []byte("This is a test")
	u.StoreFile("file", data)

	dataRE1, err := u.LoadFile("file")
	if err != nil {
		t.Error(err)
		return
	}
	dataRE2, err := u.LoadFile("file")
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(data, dataRE1) || !reflect.DeepEqual(data, dataRE2) {
		t.Error("Downloaded file is not the same", data, dataRE1, dataRE2)
		return
	}
}

func Test_AppendFile_0(t *testing.T) {
	clear()
	t.Log("AppendFile(): positve test")

	u, _ := InitUser("alice", "password")

	data := []byte{0, 1}
	u.StoreFile("file", data)

	data = cnct(data, []byte{2, 3})
	u.AppendFile("file", []byte{2, 3})

	dataRE, err := u.LoadFile("file")
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(data, dataRE) {
		t.Error("Downloaded file is not the same", data, dataRE)
		return
	}
}

func Test_AppendFile_1(t *testing.T) {
	clear()
	t.Log("AppendFile(): file not exist")

	u, _ := InitUser("alice", "password")

	err := u.AppendFile("file", []byte{2, 3})
	if err == nil {
		t.Error("append file success (should failed)")
		return
	}

}

func Test_LoadFile_0(t *testing.T) {
	clear()
	t.Log("LoadFile(): file not exist")

	u, _ := InitUser("alice", "password")

	_, err := u.LoadFile("file")
	if err == nil {
		t.Error("load file success (should failed)")
		return
	}
}

func Test_LoadFile_1(t *testing.T) {
	clear()
	t.Log("LoadFile(): cleared Datastore")

	u, _ := InitUser("alice", "password")
	data := []byte{0, 1, 2, 3}
	u.StoreFile("file", data)
	clear()
	_, err := u.LoadFile("file")
	if err == nil {
		t.Error("load file success (should failed)")
		return
	}
}

func Test_LoadFile_2(t *testing.T) {
	clear()
	t.Log("LoadFile(): cleared Datastore")

	u, _ := InitUser("alice", "password")
	data := []byte{0, 1, 2, 3}
	u.StoreFile("file", data)
	{
		dsMap := userlib.DatastoreGetMap()
		for addr := range dsMap {
			userlib.DatastoreSet(addr, userlib.RandomBytes(int(userlib.RandomBytes(1)[0])))
		}
	}
	_, err := u.LoadFile("file")
	if err == nil {
		t.Error("load file success (should failed)")
		return
	}
}

// 3 helper func to share and check share tree
func share(sender *User, senderUN string, recipient *User, recipientUN string) error {
	msg, err := sender.ShareFile("file"+senderUN, recipientUN)
	if err != nil {
		return err
	}
	err = recipient.ReceiveFile("file"+recipientUN, senderUN, msg)
	if err != nil {
		return err
	}
	return nil
}

func checkShareTree(users []*User, userUNs []string) bool {
	for i, u := range users {
		newData := userlib.RandomBytes(2)
		u.StoreFile("file"+userUNs[i], newData)
		conData := userlib.RandomBytes(2)
		u.AppendFile("file"+userUNs[i], conData)
		ok := checkConsist(users, userUNs, cnct(newData, conData))
		if !ok {
			return false
		}
	}
	return true
}

func checkConsist(users []*User, userUNs []string, expData []byte) bool {
	for i, u := range users {
		temp, _ := u.LoadFile("file" + userUNs[i])
		if !reflect.DeepEqual(temp, expData) {
			return false
		}
	}
	return true
}

func Test_ShareReceive_0(t *testing.T) {
	clear()
	t.Log("ShareFile() & Receive(): positive test")
	/*
		A
		├── B
		│   ├── C
		│   └── D
		└── E
	*/

	A, _ := InitUser("A", "a")
	B, _ := InitUser("B", "b")
	C, _ := InitUser("C", "c")
	D, _ := InitUser("D", "d")
	E, _ := InitUser("E", "e")

	data := []byte{0, 1, 2}
	A.StoreFile("fileA", data)

	err := share(A, "A", B, "B")
	if err != nil {
		t.Error(err)
		return
	}

	err = share(B, "B", C, "C")
	if err != nil {
		t.Error(err)
		return
	}

	err = share(B, "B", D, "D")
	if err != nil {
		t.Error(err)
		return
	}

	err = share(A, "A", E, "E")
	if err != nil {
		t.Error(err)
		return
	}

	ok := checkShareTree([]*User{A, B, C, D, E}, []string{"A", "B", "C", "D", "E"})
	if !ok {
		t.Error("share tree not ok")
		return
	}
}

func Test_ShareReceive_1(t *testing.T) {
	clear()
	t.Log("ShareFile() & Receive(): negative test")

	A, _ := InitUser("A", "a")
	B, _ := InitUser("B", "b")
	C, _ := InitUser("C", "c")
	A.StoreFile("fileA", []byte{0})

	// share non exist file
	_, err := A.ShareFile("not exist", "B")
	if err == nil {
		t.Error("sharing non-existing file (should failed)")
		return
	}

	// share non to non exist user
	_, err = A.ShareFile("fileA", "non exist")
	if err == nil {
		t.Error("sharing to non-existing user (should failed)")
		return
	}

	A2B, err := A.ShareFile("fileA", "B")
	if err != nil {
		t.Error(err)
		return
	}

	// incorect reciver
	err = C.ReceiveFile("fileC", "A", A2B)
	if err == nil {
		t.Error("reciving by incorrect user (should failed)")
		return
	}
	// incorrect sender parameter
	err = B.ReceiveFile("fileB", "C", A2B)
	if err == nil {
		t.Error("reciving by incorrect sender parameter (should failed)")
		return
	}
	// incorrect magic-string
	err = A.ReceiveFile("fileB", "C", string(userlib.RandomBytes(int(userlib.RandomBytes(1)[0]))))
	if err == nil {
		t.Error("reciving ramdom msg (should failed)")
		return
	}
	// existing file name
	B.StoreFile("fileB", []byte{0, 1})
	err = B.ReceiveFile("fileB", "A", A2B)
	if err == nil {
		t.Error("receive to existing filename (should failed)")
		return
	}
}

func Test_SRR_0(t *testing.T) {
	clear()
	t.Log("ShareFile() & ReceiveFile() & RevokeFile(): simple Postive test0")
	/*
		A
		├── B
		└── C
	*/
	A, _ := InitUser("A", "a")
	B, _ := InitUser("B", "b")
	C, _ := InitUser("C", "c")

	data := []byte{0, 1}
	A.StoreFile("fileA", data)

	err := share(A, "A", C, "C")
	if err != nil {
		t.Error(err)
		return
	}
	ok := checkShareTree([]*User{A, C}, []string{"A", "C"})
	if !ok {
		t.Error("share tree not ok")
		return
	}

	// share revoke share
	err = share(A, "A", B, "B")
	if err != nil {
		t.Error(err)
		return
	}
	err = A.RevokeFile("fileA", "B")
	if err != nil {
		t.Error(err)
		return
	}
	_, err = B.LoadFile("fileB")
	if err == nil {
		t.Error("revoked user load the file(should failed)")
		return
	}
	err = B.AppendFile("fileB", []byte{1, 2})
	if err == nil {
		t.Error("revoked user append the file(should failed)")
		return
	}
	err = share(A, "A", B, "B")
	if err != nil {
		t.Error(err)
		return
	}
	ok = checkShareTree([]*User{A, C}, []string{"A", "C"})
	if !ok {
		t.Error("share tree not ok")
		return
	}
}

func Test_SRR_1(t *testing.T) {
	clear()
	t.Log("ShareFile() & ReceiveFile() & RevokeFile(): simple Postive test1")

	A, _ := InitUser("A", "a")
	B, _ := InitUser("B", "b")
	C, _ := InitUser("C", "c")
	D, _ := InitUser("D", "d")
	data := []byte{0, 1}
	A.StoreFile("fileA", data)

	err := share(A, "A", B, "B")
	if err != nil {
		t.Error(err)
		return
	}
	err = share(A, "A", C, "C")
	if err != nil {
		t.Error(err)
		return
	}
	A2D, err := A.ShareFile("fileA", "D")
	if err != nil {
		t.Error(err)
		return
	}
	/*
		A
		├── B (active)
		├── C (active)
		└── D (pending)
	*/
	checkShareTree([]*User{A, B, C}, []string{"A", "B", "C"})

	err = A.RevokeFile("fileA", "B")
	if err != nil {
		t.Error(err)
		return
	}
	/*
		A
		├── B (revoked)
		├── C (active)
		└── D (pending)
	*/
	ok := checkShareTree([]*User{A, C}, []string{"A", "C"})
	if !ok {
		t.Error("share tree not ok")
		return
	}

	err = D.ReceiveFile("fileD", "A", A2D)
	if err != nil {
		t.Error(err)
		return
	}
	/*
		A
		├── B (revoked)
		├── C (active)
		└── D (active)
	*/
	checkShareTree([]*User{A, B, C}, []string{"A", "B", "C"})
	if !ok {
		t.Error("share tree not ok")
		return
	}
}
func Test_SRR_2(t *testing.T) {
	clear()
	t.Log("ShareFile() & Receive() & RevokeFile(): complex Postive test")

	A, _ := InitUser("A", "a")
	B, _ := InitUser("B", "b")
	C, _ := InitUser("C", "c")
	D, _ := InitUser("D", "d")
	E, _ := InitUser("E", "e")
	F, _ := InitUser("F", "f")
	G, _ := InitUser("G", "g")
	H, _ := InitUser("H", "h")
	I, _ := InitUser("I", "i")

	data := []byte{0, 1}
	A.StoreFile("fileA", data)

	err := share(A, "A", B, "B")
	if err != nil {
		t.Error(err)
		return
	}

	err = share(B, "B", C, "C")
	if err != nil {
		t.Error(err)
		return
	}

	err = share(C, "C", D, "D")
	if err != nil {
		t.Error(err)
		return
	}
	err = share(C, "C", E, "E")
	if err != nil {
		t.Error(err)
		return
	}
	err = share(A, "A", F, "F")
	if err != nil {
		t.Error(err)
		return
	}
	err = share(F, "F", G, "G")
	if err != nil {
		t.Error(err)
		return
	}
	err = share(G, "G", H, "H")
	if err != nil {
		t.Error(err)
		return
	}
	err = share(F, "F", I, "I")
	if err != nil {
		t.Error(err)
		return
	}

	// check the current tree
	/*
		A
		├── B
		│   └── C
		│       ├── D
		│       └── E
		└── F
		    ├── G
		    │   └── H
		    └── I
	*/
	ok := checkShareTree([]*User{A, B, C, D, E, F, G, H, I}, []string{"A", "B", "C", "D", "E", "F", "G", "H", "I"})
	if !ok {
		t.Error("share tree not ok")
		return
	}

	// revoke B
	err = A.RevokeFile("fileA", "B")
	if err != nil {
		t.Error(err)
		return
	}

	/*
		A
		├── B
		│   └── C
		│       ├── D
		│       └── E
		└── F
		    ├── G
		    │   └── H
		    └── I
	*/
	ok = checkShareTree([]*User{A, F, G, H, I}, []string{"A", "F", "G", "H", "I"})
	if !ok {
		t.Error("share tree not ok")
		return
	}
}

func Test_SRR_3(t *testing.T) {
	clear()
	t.Log("ShareFile() & Receive() & RevokeFile(): Negative test")
	/*
		A
		└── B
		    └── C
	*/
	A, _ := InitUser("A", "a")
	B, _ := InitUser("B", "b")
	C, _ := InitUser("C", "c")
	_, _ = InitUser("D", "d")

	data := []byte{0, 1}
	A.StoreFile("fileA", data)

	err := share(A, "A", B, "B")
	if err != nil {
		t.Error(err)
		return
	}
	err = share(B, "B", C, "C")
	if err != nil {
		t.Error(err)
		return
	}

	// revoke by non-owner user
	err = B.RevokeFile("fileB", "C")
	if err == nil {
		t.Error("revoked a file from non-owner user(should failed)")
	}
	// revoke from no-exist user
	err = A.RevokeFile("fileA", "not exist")
	if err == nil {
		t.Error("revoked a file from nobody(should failed)")
	}
	// revoke from never shared user
	err = A.RevokeFile("fileA", "D")
	if err == nil {
		t.Error("revoked a file from nobody(should failed)")
	}
	// double revoke from same user
	err = A.RevokeFile("fileA", "B")
	if err != nil {
		t.Error("fail to revoke a file from share user")
	}
	err = A.RevokeFile("fileA", "B")
	if err == nil {
		t.Error("double revoked a file from the same user(should failed)")
	}
	// try revoke from self
	err = A.RevokeFile("fileA", "A")
	if err == nil {
		t.Error("revoked a shared file from self(should failed)")
	}
}
