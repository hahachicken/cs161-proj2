package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	"encoding/json"
	_ "encoding/json"
	_ "errors"
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

/*
func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}
*/

func equ(a interface{}, b interface{}) bool {
	aM, _ := json.Marshal(a)
	bM, _ := json.Marshal(b)
	if len(aM) != len(bM) {
		return false
	}
	for i := 0; i < len(aM); i++ {
		if aM[i] != bM[i] {
			return false
		}
	}
	return true
}

type T struct {
	X int
	Y string
}

func TestSafeSet_Postive(t *testing.T) {
	t.Log("SafeSet() test")
	userlib.SetDebugStatus(true)
	err := SafeSet(uuid.New(), T{1, "Wei"}, userlib.RandomBytes(32), userlib.RandomBytes(32))
	if err != nil {
		t.Error()
		return
	}
}

func TestSafeGet_Postive(t *testing.T) {
	t.Log("SafeGet() postive test")
	userlib.SetDebugStatus(true)
	addr := uuid.New()
	MacKey := userlib.RandomBytes(SymKeyLen)
	CrptoKey := userlib.RandomBytes(SymKeyLen)
	putObj := T{1, "Great"}

	SafeSet(addr, putObj, CrptoKey, MacKey)
	var reObj T
	err := SafeGet(addr, &reObj, CrptoKey, MacKey)
	if err != nil {
		t.Error()
		return
	}
	if !equ(putObj, reObj) {
		t.Error()
		return
	}
}

func TestSafeGet_Negative(t *testing.T) {
	t.Log("SafeGet() negative test")
	userlib.SetDebugStatus(true)

	addr := uuid.New()
	MacKey := userlib.RandomBytes(SymKeyLen)
	CrptoKey := userlib.RandomBytes(SymKeyLen)
	tempObj := T{1, "Great"}

	{ //reset the datastore
		userlib.DatastoreClear()
		SafeSet(addr, tempObj, CrptoKey, MacKey)
		userlib.DatastoreClear()
		var re T
		err := SafeGet(addr, &re, CrptoKey, MacKey)
		if err == nil {
			t.Error()
			return
		}
	}

	{ //modify some bits
		userlib.DatastoreClear()
		SafeSet(addr, tempObj, CrptoKey, MacKey)
		userlib.DatastoreSet(addr, userlib.RandomBytes(1))
		var re T
		err := SafeGet(addr, &re, CrptoKey, MacKey)
		if err == nil {
			t.Error()
			return
		}
	}
	{
		userlib.DatastoreClear()
		SafeSet(addr, tempObj, CrptoKey, MacKey)
		userlib.DatastoreSet(addr, userlib.RandomBytes(64))
		var re T
		err := SafeGet(addr, &re, CrptoKey, MacKey)
		if err == nil {
			t.Error()
			return
		}
	}

	{ //padding some bits
		userlib.DatastoreClear()
		SafeSet(addr, tempObj, CrptoKey, MacKey)
		{
			data, _ := userlib.DatastoreGet(addr)
			data = concatenate(data, userlib.RandomBytes(10))
			userlib.DatastoreSet(addr, data)
		}
		var re T
		err := SafeGet(addr, &re, CrptoKey, MacKey)
		if err == nil {
			t.Error()
			return
		}
	}

}

func TestInitUser(t *testing.T) {
	clear()
	t.Log("InitUser() test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	// t.Log("Got user", u)
}

func TestGetUser_Postive(t *testing.T) {
	clear()
	t.Log("GetUser() positive test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	old, err := InitUser("alice", "password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	new, err := GetUser("alice", "password")

	if err != nil {
		t.Error("Fail to get user;", err)
		return
	}

	if !equ(old, new) {
		t.Error("GetUser not the same with the previous user")
		return
	}
}

func TestGetUser_Negative(t *testing.T) {
	clear()
	t.Log("GetUser() negative test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	_, err = GetUser("alice", "Password")
	if err == nil {
		t.Error("get user success(should failed);", err)
		return
	}

	_, err = GetUser("Alice", "password")
	t.Log("err:", err)
	if err == nil {
		t.Error("get user success(should failed);", err)
		return
	}
}
