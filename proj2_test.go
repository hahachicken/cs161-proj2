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

/*
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

func Test_helper_1(t *testing.T) {
	t.Log("SafeSet() test")
	userlib.SetDebugStatus(true)
	err := SafeSet(uuid.New(), "Great", userlib.RandomBytes(32), userlib.RandomBytes(32))
	if err != nil {
		t.Error()
		return
	}
}

func Test_helper_2(t *testing.T) {
	t.Log("SafeGet() postive test")
	userlib.SetDebugStatus(true)
	addr := uuid.New()
	MacKey := userlib.RandomBytes(SymKeyLen)
	CrptoKey := userlib.RandomBytes(SymKeyLen)
	putObj := "Great"

	SafeSet(addr, putObj, CrptoKey, MacKey)
	var reObj string
	err := SafeGet(addr, &reObj, CrptoKey, MacKey)
	if err != nil {
		t.Error()
		return
	}
	if !reflect.DeepEqual(putObj, reObj) {
		t.Error()
		return
	}
}

func Test_helper_3(t *testing.T) {
	t.Log("SafeGet() negative test")
	userlib.SetDebugStatus(true)

	addr := uuid.New()
	MacKey := userlib.RandomBytes(SymKeyLen)
	CrptoKey := userlib.RandomBytes(SymKeyLen)
	tempObj := "Great"

	{ //reset the datastore
		userlib.DatastoreClear()
		SafeSet(addr, tempObj, CrptoKey, MacKey)
		userlib.DatastoreClear()
		var re string
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
		var re string
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
		var re string
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
		var re string
		err := SafeGet(addr, &re, CrptoKey, MacKey)
		if err == nil {
			t.Error()
			return
		}
	}

}

func Test_1(t *testing.T) {
	clear()
	t.Log("InitUser() Postive test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user; ", err)
		return
	}
}

func Test_2(t *testing.T) {
	clear()
	t.Log("InitUser() negative test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	_, err = InitUser("alice", "f")
	if err == nil {
		// t.Error says the test fails
		t.Error("successed to initialize user (should failed); ", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	// t.Log("Got user", u)
}

func Test_3(t *testing.T) {
	clear()
	t.Log("GetUser() positive test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	old, err := InitUser("alice", "password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user; ", err)
		return
	}

	new, err := GetUser("alice", "password")

	if err != nil {
		t.Error("Fail to get user; ", err)
		return
	}

	if !reflect.DeepEqual(old, new) {
		t.Error("GetUser not the same with the init user")
		return
	}
}

func Test_4(t *testing.T) {
	clear()
	t.Log("GetUser() negative test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "password")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user; ", err)
		return
	}

	_, err = GetUser("alice", "Password")
	if err == nil {
		t.Error("get user success(should failed); ", err)
		return
	}

	_, err = GetUser("Alice", "password")
	if err == nil {
		t.Error("get user success(should failed);", err)
		return
	}
}

func Test_5(t *testing.T) {
	clear()
	t.Log("StoreFile() & LoadFile() postive test")

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error(err2)
		return
	}

	v3, err3 := u.LoadFile("file1")
	if err3 != nil {
		t.Error(err3)
		return
	}

	if !reflect.DeepEqual(v, v2) || !reflect.DeepEqual(v, v3) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func Test_6(t *testing.T) {
	clear()
	t.Log("AppendFile() positve test")

	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v1 := []byte("This is a test")
	u.StoreFile("file1", v1)

	v2 := []byte("This is append message")
	u.AppendFile("file1", v2)

	v := concatenate(v1, v2)

	vp, err := u.LoadFile("file1")
	if err != nil {
		t.Error(err)
		return
	}
	vpp, err := u.LoadFile("file1")
	if err != nil {
		t.Error(err)
		return
	}

	if !reflect.DeepEqual(v, vp) || !reflect.DeepEqual(v, vpp) {
		t.Error("Downloaded file is not the same", v, vp)
		return
	}
}

func Test_share(t *testing.T) {
	clear()

	alice, err := InitUser("alice", "foo")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	bob, err := InitUser("bob", "bar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	data := []byte("This is a test")
	alice.StoreFile("file1", data)

	msg, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error(err)
		return
	}

	err = bob.ReceiveFile("file2", "alice", msg)
	if err != nil {
		t.Error(err)
		return
	}

	file1, _ := alice.LoadFile("file1")
	file2, _ := bob.LoadFile("file2")

	if !reflect.DeepEqual(file1, file2) {
		t.Error("share files are not the same", file1, file2)
		return
	}
}

func Test_share_2(t *testing.T) {
	clear()

	alice, err := InitUser("alice", "foo")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	bob, err := InitUser("bob", "bar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	data := []byte("This is a test")
	alice.StoreFile("file1", data)

	msg, err := alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error(err)
		return
	}

	msg = msg + "a"

	err = bob.ReceiveFile("file2", "alice", msg)
	if err == nil {
		t.Error("should failed: " + err.Error())
		return
	}
}
