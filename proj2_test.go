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
	userlib.SetDebugStatus(true)

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
	userlib.SetDebugStatus(true)

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
	userlib.SetDebugStatus(true)

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
	userlib.SetDebugStatus(true)

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
	userlib.SetDebugStatus(true)

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
	t.Log("GetUser(): cleared Datastore")
	userlib.SetDebugStatus(true)

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

func Test_StoreFile_0(t *testing.T) {
	clear()
	t.Log("StoreFile(): new file")
	userlib.SetDebugStatus(true)

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
	userlib.SetDebugStatus(true)

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
	userlib.SetDebugStatus(true)

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
	userlib.SetDebugStatus(true)

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
	userlib.SetDebugStatus(true)

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
	userlib.SetDebugStatus(true)

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
	userlib.SetDebugStatus(true)

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

func Test_ShareReceive_0(t *testing.T) {
	clear()
	t.Log("ShareFile() & Receive(): positive test")
	userlib.SetDebugStatus(true)
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

	A2B, err := A.ShareFile("fileA", "B")
	if err != nil {
		t.Error(err)
		return
	}
	err = B.ReceiveFile("fileB", "A", A2B)
	if err != nil {
		t.Error(err)
		return
	}

	B2C, err := B.ShareFile("fileB", "C")
	if err != nil {
		t.Error(err)
		return
	}
	err = C.ReceiveFile("fileC", "B", B2C)
	if err != nil {
		t.Error(err)
		return
	}

	B2D, err := B.ShareFile("fileB", "D")
	if err != nil {
		t.Error(err)
		return
	}
	err = D.ReceiveFile("fileD", "B", B2D)
	if err != nil {
		t.Error(err)
		return
	}

	A2E, err := A.ShareFile("fileA", "E")
	if err != nil {
		t.Error(err)
		return
	}
	err = E.ReceiveFile("fileE", "A", A2E)
	if err != nil {
		t.Error(err)
		return
	}

	dataA, _ := A.LoadFile("fileA")
	dataB, _ := B.LoadFile("fileB")
	dataC, _ := C.LoadFile("fileC")
	dataD, _ := D.LoadFile("fileD")
	dataE, _ := E.LoadFile("fileE")
	if !reflect.DeepEqual(dataA, data) ||
		!reflect.DeepEqual(dataB, data) ||
		!reflect.DeepEqual(dataC, data) ||
		!reflect.DeepEqual(dataD, data) ||
		!reflect.DeepEqual(dataE, data) {
		t.Error("share files are not the same", data, dataA, dataB, dataC, dataD, dataE)
		return
	}

	// A update the file
	data = []byte{9, 10}
	A.StoreFile("fileA", data)

	dataA, _ = A.LoadFile("fileA")
	dataB, _ = B.LoadFile("fileB")
	dataC, _ = C.LoadFile("fileC")
	dataD, _ = D.LoadFile("fileD")
	dataE, _ = E.LoadFile("fileE")
	if !reflect.DeepEqual(dataA, data) ||
		!reflect.DeepEqual(dataB, data) ||
		!reflect.DeepEqual(dataC, data) ||
		!reflect.DeepEqual(dataD, data) ||
		!reflect.DeepEqual(dataE, data) {
		t.Error("share files are not the same", data, dataA, dataB, dataC, dataD, dataE)
		return
	}

	// B append the file
	data = cnct(data, []byte{9, 10})
	B.AppendFile("fileB", []byte{9, 10})

	dataA, _ = A.LoadFile("fileA")
	dataB, _ = B.LoadFile("fileB")
	dataC, _ = C.LoadFile("fileC")
	dataD, _ = D.LoadFile("fileD")
	dataE, _ = E.LoadFile("fileE")
	if !reflect.DeepEqual(dataA, data) ||
		!reflect.DeepEqual(dataB, data) ||
		!reflect.DeepEqual(dataC, data) ||
		!reflect.DeepEqual(dataD, data) ||
		!reflect.DeepEqual(dataE, data) {
		t.Error("share files are not the same", data, dataA, dataB, dataC, dataD, dataE)
		return
	}

	// C update the file
	data = []byte{11, 14}
	C.StoreFile("fileC", data)

	dataA, _ = A.LoadFile("fileA")
	dataB, _ = B.LoadFile("fileB")
	dataC, _ = C.LoadFile("fileC")
	dataD, _ = D.LoadFile("fileD")
	dataE, _ = E.LoadFile("fileE")
	if !reflect.DeepEqual(dataA, data) ||
		!reflect.DeepEqual(dataB, data) ||
		!reflect.DeepEqual(dataC, data) ||
		!reflect.DeepEqual(dataD, data) ||
		!reflect.DeepEqual(dataE, data) {
		t.Error("share files are not the same", data, dataA, dataB, dataC, dataD, dataE)
		return
	}
}

func Test_ShareReceive_1(t *testing.T) {
	clear()
	t.Log("ShareFile() & Receive(): negative test")
	userlib.SetDebugStatus(true)

	A, _ := InitUser("A", "a")
	B, _ := InitUser("B", "b")
	C, _ := InitUser("C", "c")
	A.StoreFile("fileA", []byte{0})

	_, err := A.ShareFile("not exist", "B")
	if err == nil {
		t.Error("sharing non-existing file (should failed)")
		return
	}

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
}

func Test_revoke(t *testing.T) {
	clear()
	t.Log("ShareFile() & Receive(): negative test")
	userlib.SetDebugStatus(true)

	A, err := InitUser("A", "a")
	B, err := InitUser("B", "b")
	C, err := InitUser("C", "c")
	D, err := InitUser("D", "d")

	data := []byte{0, 1}
	A.StoreFile("fileA", data)

	A2B, err := A.ShareFile("fileA", "B")
	if err != nil {
		t.Error(err)
		return
	}
	err = B.ReceiveFile("fileB", "A", A2B)
	if err != nil {
		t.Error(err)
		return
	}

	B2C, err := B.ShareFile("fileB", "C")
	if err != nil {
		t.Error(err)
		return
	}
	err = C.ReceiveFile("fileC", "B", B2C)
	if err != nil {
		t.Error(err)
		return
	}

	A2D, err := A.ShareFile("fileA", "D")
	if err != nil {
		t.Error(err)
		return
	}
	err = D.ReceiveFile("fileD", "A", A2D)
	if err != nil {
		t.Error(err)
		return
	}

	Adata, errA := A.LoadFile("fileA")
	Bdata, errB := B.LoadFile("fileB")
	Cdata, errC := C.LoadFile("fileC")
	Ddata, errD := D.LoadFile("fileD")
	if errA != nil || errB != nil || errD != nil {
		t.Error(errA, errB, errC, errD)
		return
	}
	if !reflect.DeepEqual(Adata, data) ||
		!reflect.DeepEqual(Bdata, data) ||
		!reflect.DeepEqual(Cdata, data) ||
		!reflect.DeepEqual(Ddata, data) {
		t.Error("share files are not the same", Adata, Bdata, Cdata, Ddata)
		return
	}

	A.RevokeFile("fileA", "B")
	_, errB = B.LoadFile("fileB")
	_, errC = C.LoadFile("fileC")
	if errB == nil || errC == nil { // should failed
		t.Error(errB, errC)
		return
	}

	data = concatenate(data, []byte{2, 3})
	D.AppendFile("fileD", []byte{2, 3})
	Adata, errA = A.LoadFile("fileA")
	Ddata, errD = D.LoadFile("fileD")
	if errA != nil || errD != nil {
		t.Error(errA, errD)
		return
	}
	if !reflect.DeepEqual(Adata, data) ||
		!reflect.DeepEqual(Ddata, data) {
		t.Error("Shared file not equal")
		return
	}

	data = concatenate(data, []byte{2, 3})
	A.AppendFile("fileA", []byte{2, 3})
	Adata, errA = A.LoadFile("fileA")
	Ddata, errD = D.LoadFile("fileD")
	if errA != nil || errD != nil {
		t.Error(errA, errD)
		return
	}
	if !reflect.DeepEqual(Adata, data) ||
		!reflect.DeepEqual(Ddata, data) {
		t.Error("Shared file not equal", Adata, Ddata, data)
		return
	}
}
