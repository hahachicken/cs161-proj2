package proj2

// CS 161 Project 2 Fall 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib

	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// some const on length
const (
	AESBlockSize = 16 // AES block size is 128 bits = 16 bytes
	SymKeyLen    = 32 // symtric key length = 256bits = 32 bytes
	MAClen       = 64 // SHA-512 = 64 bytes
)

//used in dirEntry.FileType
const (
	DEown   = iota
	DEshare = iota
)

//used in shareNode.State
const (
	SNpending = iota
	SNactive  = iota
	SNrevoked = iota
)

// User struct
type User struct {
	UserName      string
	PassWord      string
	PublicKey     userlib.PKEEncKey
	PrivateKey    userlib.PKEDecKey
	Dir           map[string]dirEntry
	addr          uuid.UUID
	rootCryptoKey []byte
	rootMACKey    []byte
}

type dirEntry struct {
	FileType      int
	NodeAddr      uuid.UUID
	NodeCryptoKey []byte
	NodeMACKey    []byte
}

type node struct {
	FileHeaderAddr      uuid.UUID
	FileHeaderCryptoKey []byte
	FileHeaderMACKey    []byte
}

type fileNode struct {
	Node    node
	Sharing map[string]shareEntry
}

type shareNode struct {
	Node  node
	State int
}

type shareEntry struct {
	Addr      uuid.UUID
	CryptoKey []byte
	MACKey    []byte
}

type fileHeader struct {
	FileLength uint
	BlockNum   uint
	Blocks     []blockPtr
}
type blockPtr struct {
	BlockAddr      uuid.UUID
	BlockCryptoKey []byte
	BlockMACKey    []byte
}

type accessToken struct {
	ShareNodeAddr      uuid.UUID
	ShareNodeCryptoKey []byte
	ShareNodeMACKey    []byte
	Certificate        []byte
}

//concatenate two slices
func concatenate(s1 []byte, s2 []byte) []byte {
	var re []byte = s1
	for i := 0; i < len(s2); i++ {
		re = append(re, s2[i])
	}
	return re
}

// SafeSet do marshal(), enc(), MAC(), DatastroeSet(). return nil upon success
func SafeSet(addr uuid.UUID, obj interface{}, cryptoKey []byte, MACKey []byte) error {
	//marshal to json text
	plainText, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	//pad to block length
	var padlen uint8 = uint8(AESBlockSize - len(plainText)%AESBlockSize)
	if padlen == 0 {
		padlen = AESBlockSize
	}
	for i := 0; uint8(i) < padlen; i++ {
		plainText = append(plainText, padlen)
	}
	//encrypt plainText
	cipherText := userlib.SymEnc(cryptoKey, userlib.RandomBytes(AESBlockSize), plainText)
	//// userlib.DebugMsg(strconv.Itoa(int(plainText[len(plainText)-4])))

	//C||MAC(C)
	MAC, err := userlib.HMACEval(MACKey, cipherText)
	if err != nil {
		return err
	}
	data := concatenate(cipherText, MAC)
	//store data
	userlib.DatastoreDelete(addr)
	userlib.DatastoreSet(addr, data)
	return nil
}

// SafeGet do DatastroeGet(), check MAC(), dec(), un-marshal(). return nil upon success
func SafeGet(addr uuid.UUID, obj interface{}, cryptoKey []byte, MACKey []byte) error {
	// fetch the data from Datastore
	data, exist := userlib.DatastoreGet(addr)
	if !exist {
		return errors.New("data on Datastroe not found")
	}
	if len(data) <= MAClen {
		return errors.New("data on Datastroe is modified")
	}

	cipherText := data[:len(data)-MAClen]
	fMAC := data[len(data)-MAClen:]

	// check MAC code
	sMAC, err := userlib.HMACEval(MACKey, cipherText)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(fMAC, sMAC) {
		return errors.New("data on Datastore is modified")
	}

	// decrypt
	plainText := userlib.SymDec(cryptoKey, cipherText)

	// discard padding
	padlen := int(plainText[len(plainText)-1])
	plainText = plainText[:len(plainText)-padlen]

	// unmarshal
	err = json.Unmarshal(plainText, obj)

	return err
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	// generare a-sym keys
	PublicKey, PrivateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	// store public key on Keystore
	publicKeyAddr := userlib.Argon2Key([]byte(username), nil, 64)
	err = userlib.KeystoreSet(hex.EncodeToString(publicKeyAddr), PublicKey)
	if err != nil {
		return nil, errors.New("username probabily been used" + err.Error())
	}

	// store user record to Datastore
	// the addr
	addr, err := uuid.FromBytes(userlib.Argon2Key([]byte(username), []byte(password), 16))
	if err != nil {
		return nil, err
	}
	// the encryption key
	cryptoKey, err := userlib.HashKDF(
		userlib.Argon2Key([]byte(password), []byte(username), SymKeyLen),
		[]byte("RootCrypto"))
	if err != nil {
		return nil, err
	}
	cryptoKey = cryptoKey[:SymKeyLen]
	// the MACKey
	MACKey, err := userlib.HashKDF(
		userlib.Argon2Key([]byte(password), []byte(username), SymKeyLen),
		[]byte("RootMAC"))
	if err != nil {
		return nil, err
	}
	MACKey = MACKey[:SymKeyLen]

	// set user and store to Dataset
	user := User{username, password, PublicKey, PrivateKey, make(map[string]dirEntry), addr, cryptoKey, MACKey}
	err = SafeSet(addr, user, cryptoKey, MACKey)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var user User
	//addr
	addr, err := uuid.FromBytes(userlib.Argon2Key([]byte(username), []byte(password), 16))
	if err != nil {
		return nil, err
	}
	// the encryption key
	cryptoKey, err := userlib.HashKDF(
		userlib.Argon2Key([]byte(password), []byte(username), SymKeyLen),
		[]byte("RootCrypto"))
	if err != nil {
		return nil, err
	}
	cryptoKey = cryptoKey[:SymKeyLen]
	// the MACKey
	MACKey, err := userlib.HashKDF(
		userlib.Argon2Key([]byte(password), []byte(username), SymKeyLen),
		[]byte("RootMAC"))
	if err != nil {
		return nil, err
	}
	MACKey = MACKey[:SymKeyLen]

	// get user to local
	err = SafeGet(addr, &user, cryptoKey, MACKey)
	if err != nil {
		return nil, errors.New("user not found or username-password unmatch; " + err.Error())
	}

	//update user metadata
	user.addr = addr
	user.rootCryptoKey = cryptoKey
	user.rootMACKey = MACKey

	return &user, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (user *User) StoreFile(filename string, data []byte) {
	if _, ok := user.Dir[filename]; ok {
		//file already exist
		return
	}

	// init and set all index strcture
	DirEntry := dirEntry{
		DEown,
		uuid.New(),
		userlib.RandomBytes(SymKeyLen),
		userlib.RandomBytes(SymKeyLen)}
	user.Dir[filename] = DirEntry

	FileNode := fileNode{
		node{uuid.New(), userlib.RandomBytes(SymKeyLen), userlib.RandomBytes(SymKeyLen)},
		make(map[string]shareEntry)}
	FileHeader := fileHeader{
		uint(len(data)),
		1,
		make([]blockPtr, 1)}
	BlockPtr := blockPtr{
		uuid.New(),
		userlib.RandomBytes(SymKeyLen),
		userlib.RandomBytes(SymKeyLen)}
	FileHeader.Blocks[0] = BlockPtr

	// push to Datastore
	SafeSet(user.addr, user, user.rootCryptoKey, user.rootMACKey)
	SafeSet(DirEntry.NodeAddr, FileNode, DirEntry.NodeCryptoKey, DirEntry.NodeMACKey)
	SafeSet(FileNode.Node.FileHeaderAddr, FileHeader, FileNode.Node.FileHeaderCryptoKey, FileNode.Node.FileHeaderMACKey)
	SafeSet(BlockPtr.BlockAddr, data, BlockPtr.BlockCryptoKey, BlockPtr.BlockMACKey)
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (user *User) AppendFile(filename string, data []byte) (err error) {
	//locally get DirEntry of "filename"
	DirEntry, exist := user.Dir[filename]
	if !exist {
		return errors.New("filename not exist")
	}

	// remotely get Node depend on own/share
	var Node node
	if DirEntry.FileType == DEown {
		var FileNode fileNode
		err = SafeGet(DirEntry.NodeAddr, &FileNode, DirEntry.NodeCryptoKey, DirEntry.NodeMACKey)
		if err != nil {
			return errors.New("AppendFile() fail to load FileNode; " + err.Error())
		}
		Node = FileNode.Node
	} else if DirEntry.FileType == DEshare {
		var ShareNode shareNode
		err = SafeGet(DirEntry.NodeAddr, &ShareNode, DirEntry.NodeCryptoKey, DirEntry.NodeMACKey)
		if err != nil {
			return errors.New("AppendFile() fail to load FileNode; " + err.Error())
		}
		Node = ShareNode.Node
	}

	// remotely get FileHeader
	var FileHeader fileHeader
	SafeGet(Node.FileHeaderAddr, &FileHeader, Node.FileHeaderCryptoKey, Node.FileHeaderMACKey)
	if err != nil {
		return errors.New("AppendFile() fail to load FileHeader; " + err.Error())
	}

	// set file header
	BlockPtr := blockPtr{uuid.New(), userlib.RandomBytes(SymKeyLen), userlib.RandomBytes(SymKeyLen)}
	FileHeader.FileLength += uint(len(data))
	FileHeader.BlockNum++
	FileHeader.Blocks = append(FileHeader.Blocks, BlockPtr)

	// put back on Datastore
	SafeSet(Node.FileHeaderAddr, FileHeader, Node.FileHeaderCryptoKey, Node.FileHeaderMACKey)
	SafeSet(BlockPtr.BlockAddr, data, BlockPtr.BlockCryptoKey, BlockPtr.BlockMACKey)
	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (user *User) LoadFile(filename string) (data []byte, err error) {
	//locally get DirEntry of "filename"
	DirEntry, exist := user.Dir[filename]
	if !exist {
		return nil, errors.New("filename not exist")
	}

	// remotely get Node depend on own/share
	var Node node
	if DirEntry.FileType == DEown {
		var FileNode fileNode
		err = SafeGet(DirEntry.NodeAddr, &FileNode, DirEntry.NodeCryptoKey, DirEntry.NodeMACKey)
		if err != nil {
			return nil, errors.New("LoadFile() fail to load FileNode; " + err.Error())
		}
		Node = FileNode.Node
	} else if DirEntry.FileType == DEshare {
		var ShareNode shareNode
		err = SafeGet(DirEntry.NodeAddr, &ShareNode, DirEntry.NodeCryptoKey, DirEntry.NodeMACKey)
		if err != nil {
			return nil, errors.New("LoadFile() fail to load FileNode; " + err.Error())
		}
		Node = ShareNode.Node
	}

	// remotely get FileHeader
	var FileHeader fileHeader
	SafeGet(Node.FileHeaderAddr, &FileHeader, Node.FileHeaderCryptoKey, Node.FileHeaderMACKey)
	if err != nil {
		return nil, errors.New("LoadFile() fail to load FileHeader; " + err.Error())
	}

	// get the file data
	var temp []byte
	for i := 0; i < int(FileHeader.BlockNum); i++ {
		BlockPtr := FileHeader.Blocks[i]
		err = SafeGet(BlockPtr.BlockAddr, &temp, BlockPtr.BlockCryptoKey, BlockPtr.BlockMACKey)
		if err != nil {
			return nil, errors.New("LoadFile() fail to load data blocks; " + err.Error())
		}
		data = concatenate(data, temp)
	}
	return data, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	return
}
