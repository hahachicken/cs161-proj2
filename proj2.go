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

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

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

//used in node.State
const (
	NODE_own     = iota
	NODE_pending = iota
	NODE_active  = iota
	NODE_revoked = iota
)

type ptr struct {
	Addr      uuid.UUID
	CryptoKey []byte
	MACKey    []byte
}

// User struct
type User struct {
	// public fields
	PrivateKey userlib.PKEDecKey
	SignKey    userlib.DSSignKey
	Dir        map[string]ptr
	// private fields
	username string
	password string
	rootPtr  ptr
}

type node struct {
	State     int
	HeaderPtr ptr
	Sharing   map[string]ptr
}

type header struct {
	FileLength uint
	BlockPtrs  []ptr
}

// helper func
// concatenate two slices
func concatenate(s1 []byte, s2 []byte) []byte {
	var re []byte = s1
	for i := 0; i < len(s2); i++ {
		re = append(re, s2[i])
	}
	return re
}

// init a new random ptr
func newPtr() ptr {
	return ptr{
		uuid.New(),
		userlib.RandomBytes(SymKeyLen),
		userlib.RandomBytes(SymKeyLen)}
}

// SafeSet do marshal(), enc(), MAC(), DatastroeSet(). return nil upon success
func safeSet(addr uuid.UUID, obj interface{}, cryptoKey []byte, MACKey []byte) error {
	//marshal to json text
	plainText, err := json.Marshal(obj)
	if err != nil {
		return errors.New("SafeSet() < " + err.Error() + " >")
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
		return errors.New("SafeSet() < " + err.Error() + " >")
	}
	data := concatenate(cipherText, MAC)
	//store data
	userlib.DatastoreDelete(addr)
	userlib.DatastoreSet(addr, data)
	return nil
}

// SafeGet do DatastroeGet(), check MAC(), dec(), un-marshal(). return nil upon success
func safeGet(addr uuid.UUID, obj interface{}, cryptoKey []byte, MACKey []byte) error {
	// fetch the data from Datastore
	data, exist := userlib.DatastoreGet(addr)
	if !exist {
		return errors.New("SafeGet(data on Datastroe not found)")
	}
	if len(data) <= MAClen {
		return errors.New("SafeGet(data on Datastroe is modified)")
	}

	cipherText := data[:len(data)-MAClen]
	fMAC := data[len(data)-MAClen:]

	// check MAC code
	sMAC, err := userlib.HMACEval(MACKey, cipherText)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(fMAC, sMAC) {
		return errors.New("SafeGet(data on Datastore is modified)")
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

// PtrSet set the obj at p.Addr using SafeSet()
func ptrSet(p ptr, obj interface{}) error {
	err := safeSet(p.Addr, obj, p.CryptoKey, p.MACKey)
	if err != nil {
		return errors.New("PtrSet() < " + err.Error() + " >")
	}
	return nil
}

// PtrGet get the Obj at Ptr using SafeGet()
func ptrGet(p ptr, obj interface{}) error {
	err := safeGet(p.Addr, obj, p.CryptoKey, p.MACKey)
	if err != nil {
		return errors.New("PtrGet() < " + err.Error() + " >")
	}
	return nil
}

// GenRootPtr compute addr, crypto, MAC key of User
func rootPtr(username string, password string) (ptr, error) {
	// the addr
	Addr, err := uuid.FromBytes(userlib.Argon2Key([]byte(username), []byte(password), 16))
	if err != nil {
		return ptr{}, errors.New("genRootPtr() < " + err.Error() + " >")
	}
	// encryption key
	CryptoKey, err := userlib.HashKDF(
		userlib.Argon2Key([]byte(password), []byte(username), SymKeyLen),
		[]byte("RootCrypto"))
	if err != nil {
		return ptr{}, errors.New("genRootPtr() < " + err.Error() + " >")
	}
	CryptoKey = CryptoKey[:SymKeyLen]
	// MACK ey
	MACKey, err := userlib.HashKDF(
		userlib.Argon2Key([]byte(password), []byte(username), SymKeyLen),
		[]byte("RootMAC"))
	if err != nil {
		return ptr{}, errors.New("genRootPtr() < " + err.Error() + " >")
	}
	MACKey = MACKey[:SymKeyLen]

	return ptr{Addr, CryptoKey, MACKey}, nil
}

func getPublic(username string) (userlib.PKEEncKey, userlib.DSVerifyKey, error) {
	PublicKeyAddr := userlib.Argon2Key([]byte(username), []byte("PKE"), 64)
	PublicKey, exist := userlib.KeystoreGet(hex.EncodeToString(PublicKeyAddr))
	if !exist {
		return userlib.PKEEncKey{}, userlib.DSVerifyKey{}, errors.New("getPublic(user not exist)")
	}

	VerifyKeyAddr := userlib.Argon2Key([]byte(username), []byte("DS"), 64)
	VerifyKey, exist := userlib.KeystoreGet(hex.EncodeToString(VerifyKeyAddr))
	if !exist {
		return userlib.PKEEncKey{}, userlib.DSVerifyKey{}, errors.New("getPublic(user not exist)")
	}
	return PublicKey, VerifyKey, nil
}

// InitUser creates a user.  It will only be called once for a user
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
func InitUser(username string, password string) (Userdataptr *User, err error) {
	// generare a-sym keys
	PublicKey, PrivateKey, _ := userlib.PKEKeyGen()
	SignKey, VerifyKey, _ := userlib.DSKeyGen()

	// store public key on Keystore
	PublicKeyAddr := userlib.Argon2Key([]byte(username), []byte("PKE"), 64)
	err = userlib.KeystoreSet(hex.EncodeToString(PublicKeyAddr), PublicKey)
	if err != nil {
		return nil, errors.New("InitUser(username might been used) <" + err.Error() + ">")
	}
	// store verify key on Keystore
	VerifyKeyAddr := userlib.Argon2Key([]byte(username), []byte("DS"), 64)
	err = userlib.KeystoreSet(hex.EncodeToString(VerifyKeyAddr), VerifyKey)
	if err != nil {
		return nil, errors.New("InitUser(username might been used) <" + err.Error() + ">")
	}

	// store user record to Datastore
	RootPtr, err := rootPtr(username, password)
	if err != nil {
		return nil, errors.New("InitUser() < " + err.Error() + " >")
	}

	// set user and store to Dataset
	user := User{PrivateKey, SignKey, make(map[string]ptr), username, password, RootPtr}
	err = ptrSet(RootPtr, user)
	if err != nil {
		return nil, errors.New("InitUser() < " + err.Error() + " >")
	}

	return &user, nil
}

// GetUser fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (UserData *User, err error) {
	var Userdata User

	RootPtr, err := rootPtr(username, password)
	if err != nil {
		return nil, errors.New("genRootPtr(calcuate root ptr failed) < " + err.Error() + " >")
	}

	// get user to local
	err = ptrGet(RootPtr, &Userdata)
	if err != nil {
		return nil, errors.New("genRootPtr(get from root ptr failed) < " + err.Error() + " >")
	}

	//update User private fields
	Userdata.username = username
	Userdata.password = password
	Userdata.rootPtr = RootPtr

	return &Userdata, nil
}

func (UserData *User) getNode(filename string) (node, error) {
	NodePtr, exist := UserData.Dir[filename]
	if !exist {
		return node{}, errors.New("getNode(file not exist)")
	}

	var FN node
	err := ptrGet(NodePtr, &FN)
	if err != nil {
		return node{}, errors.New("getNode(fail to load fileNode) < " + err.Error() + " >")
	}

	if FN.State == NODE_pending {
		return node{}, errors.New("Datastore inconsistant")
	}
	if FN.State == NODE_revoked {
		userlib.DatastoreDelete(NodePtr.Addr)
		delete(UserData.Dir, filename)
		err = ptrSet(UserData.rootPtr, UserData)
		if err != nil {
			return node{}, errors.New("getNode(failed to remove revoked file entry in User) < " + err.Error() + " >")
		}
		return node{}, errors.New("getNode(NO permission to access a revoked file node)")
	}

	return FN, nil
}

// StoreFile stores a file in the datastore.
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (UserData *User) StoreFile(filename string, data []byte) {
	//file already exist
	NodePtr, exist := UserData.Dir[filename]
	if exist {
		FN, err := UserData.getNode(filename)
		if err != nil {
			return
		}

		var FH header
		err = ptrGet(FN.HeaderPtr, &FH)
		if err != nil {
			return
		}

		// remove all old blocks
		for _, BlockPtr := range FH.BlockPtrs {
			userlib.DatastoreDelete(BlockPtr.Addr)
		}

		// update fileHeader
		FH.FileLength = uint(len(data))
		FH.BlockPtrs = []ptr{
			newPtr()}
		err = ptrSet(FN.HeaderPtr, FH)
		if err != nil {
			return
		}

		// set data
		err = ptrSet(FH.BlockPtrs[0], data)
		if err != nil {
			return
		}
		return
	}
	// it is new file
	// init all index strcture
	NodePtr = newPtr()
	UserData.Dir[filename] = NodePtr

	FN := node{
		NODE_own,
		newPtr(),
		make(map[string]ptr)}

	FH := header{
		uint(len(data)),
		[]ptr{newPtr()}}

	// Update Datastore
	ptrSet(UserData.rootPtr, UserData)
	ptrSet(NodePtr, FN)
	ptrSet(FN.HeaderPtr, FH)
	ptrSet(FH.BlockPtrs[0], data)
}

// AppendFile adds on to an existing file.
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (UserData *User) AppendFile(filename string, data []byte) (err error) {
	//locally get DirEntry of "filename"
	FN, err := UserData.getNode(filename)
	if err != nil {
		return errors.New("AppendFile(fail to get Node) < " + err.Error() + " >")
	}

	// remotely get FileHeader
	var FH header
	err = ptrGet(FN.HeaderPtr, &FH)
	if err != nil {
		return errors.New("AppendFile(fail to load FileHeader) < " + err.Error() + " >")
	}

	// set file header
	FH.FileLength += uint(len(data))
	NewBlockPtr := newPtr()
	FH.BlockPtrs = append(FH.BlockPtrs, NewBlockPtr)

	// put back on Datastore
	ptrSet(FN.HeaderPtr, FH)
	ptrSet(NewBlockPtr, data)
	return nil
}

// LoadFile loads a file from the Datastore.
// It should give an error if the file is corrupted in any way.
func (UserData *User) LoadFile(filename string) (data []byte, err error) {
	FN, err := UserData.getNode(filename)
	if err != nil {
		return nil, errors.New("LoadFile(fail to get Node) < " + err.Error() + " >")
	}

	// remotely get FileHeader
	var FH header
	err = ptrGet(FN.HeaderPtr, &FH)
	if err != nil {
		return nil, errors.New("LoadFile(fail to load FileHeader) < " + err.Error() + " >")
	}

	// get the file data
	var temp []byte
	for _, BlockPtr := range FH.BlockPtrs {
		err = ptrGet(BlockPtr, &temp)
		if err != nil {
			return nil, errors.New("LoadFile(fail to load data blocks) < " + err.Error() + " >")
		}
		data = concatenate(data, temp)
	}
	return data, nil
}

type token struct {
	Msg  []byte
	Sign []byte
}
type eptr struct {
	EAddr      []byte
	ECryptoKey []byte
	EMACKey    []byte
}

func ptrTOeptr(p ptr, pubKey userlib.PKEEncKey) (eptr, error) {
	// Addr
	MAddr, err := json.Marshal(p.Addr)
	if err != nil {
		return eptr{}, errors.New("ptrTOeptr() < " + err.Error() + " >")
	}
	EAddr, err := userlib.PKEEnc(pubKey, MAddr)
	if err != nil {
		return eptr{}, errors.New("ptrTOeptr() < " + err.Error() + " >")
	}
	// CryptoKey
	ECryptoKey, err := userlib.PKEEnc(pubKey, p.CryptoKey)
	if err != nil {
		return eptr{}, errors.New("ptrTOeptr() < " + err.Error() + " >")
	}
	// MAC key
	EMACKey, err := userlib.PKEEnc(pubKey, p.MACKey)
	if err != nil {
		return eptr{}, errors.New("ptrTOeptr() < " + err.Error() + " >")
	}

	return eptr{EAddr, ECryptoKey, EMACKey}, nil
}

func eptrTOPtr(ep eptr, privKey userlib.PKEDecKey) (ptr, error) {
	// Addr
	MAddr, err := userlib.PKEDec(privKey, ep.EAddr)
	if err != nil {
		return ptr{}, errors.New("eptrTOptr() < " + err.Error() + " >")
	}
	var Addr uuid.UUID
	err = json.Unmarshal(MAddr, &Addr)
	if err != nil {
		return ptr{}, errors.New("eptrTOptr() < " + err.Error() + " >")
	}
	// CryptoKey
	CryptoKey, err := userlib.PKEDec(privKey, ep.ECryptoKey)
	if err != nil {
		return ptr{}, err
	}
	// MACKey
	MACKey, err := userlib.PKEDec(privKey, ep.EMACKey)
	if err != nil {
		return ptr{}, err
	}

	return ptr{Addr, CryptoKey, MACKey}, nil
}

func eptrTOmbytes(ep eptr, sigKey userlib.DSSignKey) ([]byte, error) {
	msg, err := json.Marshal(ep)
	if err != nil {
		return make([]byte, 0), errors.New("eptrTOmbyte() < " + err.Error() + " >")
	}
	sign, err := userlib.DSSign(sigKey, msg)
	if err != nil {
		return make([]byte, 0), errors.New("eptrTOmbyte() < " + err.Error() + " >")
	}
	mbytes, err := json.Marshal(token{msg, sign})
	if err != nil {
		return make([]byte, 0), errors.New("eptrTOmbyte() < " + err.Error() + " >")
	}
	return mbytes, nil
}

func mbytesTOeptr(mbytes []byte, verKey userlib.DSVerifyKey) (eptr, error) {
	// unmarshal to token
	var Token token
	err := json.Unmarshal(mbytes, &Token)
	if err != nil {
		return eptr{}, errors.New("mbyteTOeptr() < " + err.Error() + " >")
	}
	// verify
	err = userlib.DSVerify(verKey, Token.Msg, Token.Sign)
	if err != nil {
		return eptr{}, errors.New("mbyteTOeptr(MagicString modified) < " + err.Error() + " >")
	}
	// unmarshal to eptr
	var Eptr eptr
	err = json.Unmarshal(Token.Msg, &Eptr)
	if err != nil {
		return eptr{}, errors.New("mbyteTOeptr() < " + err.Error() + " >")
	}

	return Eptr, nil
}

// ShareFile creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.
// This enables the recipient to access the encrypted file as well
// for reading/appending.
// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (UserData *User) ShareFile(filename string, recipient string) (string, error) {
	FN, err := UserData.getNode(filename)
	if err != nil {
		return "", errors.New("ShareFile(fail to get Node) < " + err.Error() + " >")
	}

	if _, exist := FN.Sharing[recipient]; exist {
		return "", errors.New("ShareFile(already shared file with recipient)")
	}
	FN.Sharing[recipient] = newPtr()
	err = ptrSet(UserData.Dir[filename], FN)
	if err != nil {
		return "", errors.New("ShareFile(failed to add share entry in fineNode) < " + err.Error() + " >")
	}

	// init and set new ShareNode for this share relation
	ShareNode := node{
		NODE_pending,
		FN.HeaderPtr,
		make(map[string]ptr)}
	err = ptrSet(FN.Sharing[recipient], ShareNode)
	if err != nil {
		return "", errors.New("ShareFile(failed to put ShareNode in Datastore) < " + err.Error() + " >")
	}

	// generate AccessToken
	rePubKey, _, err := getPublic(recipient)
	if err != nil {
		return "", err
	}
	Eptr, err := ptrTOeptr(FN.Sharing[recipient], rePubKey)
	if err != nil {
		return "", errors.New("ShareFile() < " + err.Error() + " >")
	}
	mBytes, err := eptrTOmbytes(Eptr, UserData.SignKey)
	if err != nil {
		return "", errors.New("ShareFile() < " + err.Error() + " >")
	}

	return string(mBytes), nil
}

// ReceiveFile :
// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (UserData *User) ReceiveFile(filename string, sender string, magicString string) error {
	mBytes := []byte(magicString)
	_, seVerify, err := getPublic(sender)
	if err != nil {
		return errors.New("ReceiveFile(\"sender\" may incorrect) < " + err.Error() + " >")
	}

	Eptr, err := mbytesTOeptr(mBytes, seVerify)
	if err != nil {
		return errors.New("ReceiveFile() < " + err.Error() + " >")
	}
	ShareNodePtr, err := eptrTOPtr(Eptr, UserData.PrivateKey)
	if err != nil {
		return errors.New("ReceiveFile() < " + err.Error() + " >")
	}

	// update ShareNode.State
	var SN node
	err = ptrGet(ShareNodePtr, &SN)
	if err != nil {
		return errors.New("ReceiveFile(fail to get ShareNode) < " + err.Error() + " >")
	}
	SN.State = NODE_active
	err = ptrSet(ShareNodePtr, SN)
	if err != nil {
		return errors.New("ReceiveFile(fail to update ShareNode.State to NODE_active) < " + err.Error() + " >")
	}

	UserData.Dir[filename] = ShareNodePtr
	err = ptrSet(UserData.rootPtr, UserData)
	if err != nil {
		return errors.New("ReceiveFile(fail to update file entry in User) < " + err.Error() + " >")
	}
	return nil
}

func setRevoke(p ptr) error {
	var Node node
	err := ptrGet(p, &Node)
	if err != nil {
		return errors.New("setRevoke(fail to get the node) < " + err.Error() + " >")
	}
	Node.State = NODE_revoked
	err = ptrSet(p, Node)
	if err != nil {
		return errors.New("setRevoke(faile to update the node) < " + err.Error() + " >")
	}
	return nil
}

// RevokeFile : Removes target user's access.
func (UserData *User) RevokeFile(filename string, targetUsername string) (err error) {
	FileNode, err := UserData.getNode(filename)
	if err != nil {
		return errors.New("RevokeFile(faile to get node) < " + err.Error() + " >")
	}
	if FileNode.State != NODE_own {
		return errors.New("RevokeFile(not the owner of the file)")
	}

	// start invalidating the target shareNode and its sub-shareNodes
	directShareNodePtr, exist := FileNode.Sharing[targetUsername]
	if !exist {
		return errors.New("RevokeFile(never shared this file with the user before)")
	}
	var directSN node
	err = ptrGet(directShareNodePtr, &directSN)
	if !exist {
		return errors.New("RevokeFile(fail to get direct shareNode) < " + err.Error() + " >")
	}
	directSN.State = NODE_revoked
	ptrSet(directShareNodePtr, directSN)
	err = directSN.boardcastShareNode_revoke()
	if !exist {
		return errors.New("RevokeFile(fail to invalidate all shareNode) < " + err.Error() + " >")
	}

	// start moving file to a new place
	// get data
	data, err := UserData.LoadFile(filename)
	if err != nil {
		return errors.New("RevokeFile(fail to get data) < " + err.Error() + " >")
	}
	// remove the file header and all data blocks
	var oldFH header
	err = ptrGet(FileNode.HeaderPtr, &oldFH)
	if err != nil {
		return errors.New("RevokeFile(fail to get fileHeader) < " + err.Error() + " >")
	}
	for _, BlockPtr := range oldFH.BlockPtrs {
		userlib.DatastoreDelete(BlockPtr.Addr) // delete data
	}
	userlib.DatastoreDelete(FileNode.HeaderPtr.Addr) // delete old fileHeader

	// init and set new File Header
	newFHPtr := newPtr()
	newFH := header{uint(len(data)), []ptr{newPtr()}}
	err = ptrSet(newFHPtr, newFH)
	if err != nil {
		return errors.New("RevokeFile(fail to set new fileHeader) < " + err.Error() + " >")
	}
	// set data to new place
	err = ptrSet(newFH.BlockPtrs[0], data)
	if err != nil {
		return errors.New("RevokeFile(fail to move data) < " + err.Error() + " >")
	}

	// boardcast everyone the new fileHeader Ptr
	FileNode.HeaderPtr = newFHPtr
	delete(FileNode.Sharing, targetUsername)
	err = ptrSet(UserData.Dir[filename], FileNode)
	if err != nil {
		return errors.New("RevokeFile(fail to update fileNode on new fileHeaderPtr) < " + err.Error() + " >")
	}
	err = FileNode.boardcastShareNode_HeaderPtr()

	return nil
}

// will boardcast self.HeaderPtr to all ShareNode pointted by self.Sharing
func (Node *node) boardcastShareNode_HeaderPtr() (err error) {
	if len(Node.Sharing) == 0 {
		return nil
	}
	for _, SNptr := range Node.Sharing {
		var SN node
		err = ptrGet(SNptr, &SN)
		if err != nil {
			return errors.New("boardcastShareNode_HeaderPtr() < " + err.Error() + " >")
		}
		SN.HeaderPtr = Node.HeaderPtr
		err = ptrSet(SNptr, SN)
		if err != nil {
			return errors.New("boardcastShareNode_HeaderPtr() < " + err.Error() + " >")
		}
		SN.boardcastShareNode_HeaderPtr()
	}
	return nil
}

// will set all shareNode pointted by self.Sharing and their sub-shareNode to NODE_revoke
// excludeing self
func (Node *node) boardcastShareNode_revoke() (err error) {
	if len(Node.Sharing) == 0 {
		return nil
	}
	for _, SNptr := range Node.Sharing {
		var SN node
		err = ptrGet(SNptr, &SN)
		if err != nil {
			return errors.New("boardcastShareNode_revoke() < " + err.Error() + " >")
		}
		SN.State = NODE_revoked
		err = ptrSet(SNptr, SN)
		if err != nil {
			return errors.New("boardcastShareNode_revoke() < " + err.Error() + " >")
		}
		SN.boardcastShareNode_revoke()
	}
	return nil
}
