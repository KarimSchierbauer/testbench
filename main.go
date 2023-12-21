package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/csv"
	"math/big"

	"github.com/algorand/falcon"
	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"

	"log"
	"os"
	"strconv"
	"time"

	kyber "github.com/kudelskisecurity/crystals-go/crystals-kyber"
	"golang.org/x/crypto/sha3"

	"crypto"

	"github.com/google/uuid"
)

type record struct {
	ID             string
	Type           string
	ElapsedTime    int64
	PrivateKeySize string
	PublicKeySize  string
	hashString     string
	signatureSize  string
}

type key struct {
	curve      elliptic.Curve
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
	R          *big.Int
	S          *big.Int
}

type kyberkey struct {
	curve      elliptic.Curve
	PrivateKey []byte
	PublicKey  []byte
}

type dilithiumkey struct {
	curve      elliptic.Curve
	PrivateKey dilithium.PrivateKey
	PublicKey  dilithium.PublicKey
	Sig        []byte
}

type falconkey struct {
	curve      elliptic.Curve
	PrivateKey falcon.PrivateKey
	PublicKey  falcon.PublicKey
	Sig        *falcon.CompressedSignature
}

type sphincskey struct {
	curve      elliptic.Curve
	PrivateKey sphincs.SPHINCS_SK
	PublicKey  sphincs.SPHINCS_PK
	Sig        *sphincs.SPHINCS_SIG
}

func newRecord(id string, recordType string, elapsedTime int64, privateKey string, publicKey string, hashString string, signatureSize string) record {
	return record{id, recordType, elapsedTime, privateKey, publicKey, hashString, signatureSize}
}

func main() {
	iterations, _ := strconv.Atoi(os.Args[1])
	log.Printf("Running %d iterations", iterations)
	var records []record = make([]record, iterations)
	var recordType string
	var keyStore []key = make([]key, iterations)
	var kyberKeyStore []kyberkey = make([]kyberkey, iterations)
	var dilithiumKeyStore []dilithiumkey = make([]dilithiumkey, iterations)
	var falconKeyStore []falconkey = make([]falconkey, iterations)
	var sphincsKeyStore []sphincskey = make([]sphincskey, iterations)
	byteTest := []byte("Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed dia")

	for i := 0; i < iterations; i++ {
		id := uuid.New().String()
		recordType = "SHA256"
		start := time.Now()
		hashString := sha256.New()
		hashString.Write(byteTest)
		//log.Printf("SHA256: %x", hashString)
		elapsed := time.Since(start).Nanoseconds()
		records[i] = newRecord(id, recordType, elapsed, "", "", "", "")
		//log.Printf("Record: %s", records[i])
	}

	for i := 0; i < iterations; i++ {
		id := uuid.New().String()
		recordType = "SHA512"
		start := time.Now()
		hashString := sha512.New()
		hashString.Write(byteTest)
		//log.Printf("SHA256: %x", hashString)
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
		//log.Printf("Record: %s", records[i])
	}

	for i := 0; i < iterations; i++ {
		id := uuid.New().String()
		recordType = "SHA3_256"
		start := time.Now()
		hashString := sha3.New256()
		hashString.Write(byteTest)
		//log.Printf("SHA256: %x", hashString)
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
		//log.Printf("Record: %s", records[i])
	}

	for i := 0; i < iterations; i++ {
		id := uuid.New().String()
		recordType = "SHA3_512"
		start := time.Now()
		hashString := sha3.New512()
		hashString.Write(byteTest)
		//log.Printf("SHA256: %x", hashString)
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
		//log.Printf("Record: %s", records[i])
	}

	for j := 0; j < iterations; j++ {
		id := uuid.New().String()
		start := time.Now()
		recordType = "ECDSA_keygen"
		curve := elliptic.P256()
		privKey, _ := ecdsa.GenerateKey(curve, rand.Reader)
		pubKey := privKey.Public()
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
		keyStore[j] = key{curve, privKey, pubKey, nil, nil}
	}

	for k := 0; k < iterations; k++ {

		id := uuid.New().String()
		start := time.Now()
		recordType = "ECDSA_sign"
		privateKey, ok := keyStore[k].PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			log.Fatalf("failed to convert private key to *ecdsa.PrivateKey")
		}
		r, s, _ := ecdsa.Sign(rand.Reader, privateKey, byteTest)
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
		keyStore[k] = key{keyStore[k].curve, keyStore[k].PrivateKey, keyStore[k].PublicKey, r, s}
	}

	for k := 0; k < iterations; k++ {

		id := uuid.New().String()
		start := time.Now()
		recordType = "ECDSA_verify"
		publicKey, _ := keyStore[k].PublicKey.(*ecdsa.PublicKey)
		signVerified := ecdsa.Verify(publicKey, byteTest, keyStore[k].R, keyStore[k].S)
		_ = signVerified
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
	}

	// Crystal Kyber

	for k := 0; k < iterations; k++ {
		id := uuid.New().String()
		start := time.Now()
		recordType = "Kyber_keygen_512"
		ky := kyber.NewKyber512()
		pubKey, privKey := ky.KeyGen(nil)
		elapsed := time.Since(start).Nanoseconds()
		kyberKeyStore[k] = kyberkey{nil, privKey, pubKey}
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
	}

	for k := 0; k < iterations; k++ {
		id := uuid.New().String()
		start := time.Now()
		recordType = "Kyber_encrypt_512"
		ky := kyber.NewKyber512()
		packedPk := ky.PackPK(ky.UnpackPK(kyberKeyStore[k].PublicKey))
		encryptedText := ky.Encrypt(packedPk, byteTest, nil)
		_ = encryptedText
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
	}

	for k := 0; k < iterations; k++ {
		id := uuid.New().String()
		start := time.Now()
		recordType = "Kyber_keygen_768"
		ky := kyber.NewKyber768()
		pubKey, privKey := ky.KeyGen(nil)
		elapsed := time.Since(start).Nanoseconds()
		kyberKeyStore[k] = kyberkey{nil, privKey, pubKey}
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
	}

	for k := 0; k < iterations; k++ {
		id := uuid.New().String()
		start := time.Now()
		recordType = "Kyber_encrypt_768"
		ky := kyber.NewKyber768()
		packedPk := ky.PackPK(ky.UnpackPK(kyberKeyStore[k].PublicKey))
		encryptedText := ky.Encrypt(packedPk, byteTest, nil)
		_ = encryptedText
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
	}

	for k := 0; k < iterations; k++ {
		id := uuid.New().String()
		start := time.Now()
		recordType = "Kyber_keygen_1024"
		ky := kyber.NewKyber1024()
		pubKey, privKey := ky.KeyGen(nil)
		elapsed := time.Since(start).Nanoseconds()
		kyberKeyStore[k] = kyberkey{nil, privKey, pubKey}
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
	}

	for k := 0; k < iterations; k++ {
		id := uuid.New().String()
		start := time.Now()
		recordType = "Kyber_encrypt_1024"
		ky := kyber.NewKyber1024()
		packedPk := ky.PackPK(ky.UnpackPK(kyberKeyStore[k].PublicKey))
		encryptedText := ky.Encrypt(packedPk, byteTest, nil)
		_ = encryptedText
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
	}

	// Dilithium
	for d := 0; d < iterations; d++ {
		var Mode2 = dilithium.Mode2
		id := uuid.New().String()
		start := time.Now()
		recordType = "Dilithium2_keygen"
		pubKey, privKey, _ := Mode2.GenerateKey(rand.Reader)
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, strconv.Itoa(Mode2.PrivateKeySize()), strconv.Itoa(Mode2.PublicKeySize()), "", ""))
		dilithiumKeyStore[d] = dilithiumkey{nil, privKey, pubKey, nil}
	}

	for d := 0; d < iterations; d++ {
		var Mode2 = dilithium.Mode2
		id := uuid.New().String()
		start := time.Now()
		recordType = "Dilithium2_sign"
		signature, _ := dilithiumKeyStore[d].PrivateKey.Sign(rand.Reader, byteTest, crypto.Hash(0))
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", strconv.Itoa(Mode2.SignatureSize())))
		dilithiumKeyStore[d] = dilithiumkey{nil, dilithiumKeyStore[d].PrivateKey, dilithiumKeyStore[d].PublicKey, signature}
	}

	for d := 0; d < iterations; d++ {

		id := uuid.New().String()
		start := time.Now()
		recordType = "Dilithium2_verify"
		verifiedSignature := dilithium.Mode2.Verify(dilithiumKeyStore[d].PublicKey, byteTest, dilithiumKeyStore[d].Sig)
		_ = verifiedSignature
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))

	}

	for d := 0; d < iterations; d++ {
		var Mode3 = dilithium.Mode3
		id := uuid.New().String()
		start := time.Now()
		recordType = "Dilithium3_keygen"
		pubKey, privKey, _ := Mode3.GenerateKey(rand.Reader)
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, strconv.Itoa(Mode3.PrivateKeySize()), strconv.Itoa(Mode3.PublicKeySize()), "", ""))
		dilithiumKeyStore[d] = dilithiumkey{nil, privKey, pubKey, nil}
	}

	for d := 0; d < iterations; d++ {
		var Mode3 = dilithium.Mode3
		id := uuid.New().String()
		start := time.Now()
		recordType = "Dilithium3_sign"
		signature, _ := dilithiumKeyStore[d].PrivateKey.Sign(rand.Reader, byteTest, crypto.Hash(0))
		_ = signature
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", strconv.Itoa(Mode3.SignatureSize())))
		dilithiumKeyStore[d] = dilithiumkey{nil, dilithiumKeyStore[d].PrivateKey, dilithiumKeyStore[d].PublicKey, signature}
	}

	for d := 0; d < iterations; d++ {

		id := uuid.New().String()
		start := time.Now()
		recordType = "Dilithium3_verify"
		verifiedSignature := dilithium.Mode3.Verify(dilithiumKeyStore[d].PublicKey, byteTest, dilithiumKeyStore[d].Sig)
		_ = verifiedSignature
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))

	}

	for d := 0; d < iterations; d++ {
		var Mode5 = dilithium.Mode5
		id := uuid.New().String()
		start := time.Now()
		recordType = "Dilithium5_keygen"
		pubKey, privKey, _ := Mode5.GenerateKey(rand.Reader)
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, strconv.Itoa(Mode5.PrivateKeySize()), strconv.Itoa(Mode5.PublicKeySize()), "", ""))
		dilithiumKeyStore[d] = dilithiumkey{nil, privKey, pubKey, nil}
	}

	for d := 0; d < iterations; d++ {
		var Mode5 = dilithium.Mode5
		id := uuid.New().String()
		start := time.Now()
		recordType = "Dilithium5_sign"
		signature, _ := dilithiumKeyStore[d].PrivateKey.Sign(rand.Reader, byteTest, crypto.Hash(0))
		_ = signature
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", strconv.Itoa(Mode5.SignatureSize())))
		dilithiumKeyStore[d] = dilithiumkey{nil, dilithiumKeyStore[d].PrivateKey, dilithiumKeyStore[d].PublicKey, signature}
	}

	for d := 0; d < iterations; d++ {

		id := uuid.New().String()
		start := time.Now()
		recordType = "Dilithium5_verify"
		verifiedSignature := dilithium.Mode5.Verify(dilithiumKeyStore[d].PublicKey, byteTest, dilithiumKeyStore[d].Sig)
		_ = verifiedSignature
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))

	}

	// Falcon

	for f := 0; f < iterations; f++ {
		id := uuid.New().String()
		start := time.Now()
		recordType = "Falcon512_keygen"
		pubKey, privKey, _ := falcon.GenerateKey(nil)
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, strconv.Itoa(falcon.PrivateKeySize), strconv.Itoa(falcon.PublicKeySize), "", ""))
		falconKeyStore[f] = falconkey{nil, privKey, pubKey, nil}
	}

	for f := 0; f < iterations; f++ {

		id := uuid.New().String()
		start := time.Now()
		recordType = "Falcon512_sign"
		signature, _ := falconKeyStore[f].PrivateKey.SignCompressed(byteTest)
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", strconv.Itoa(falcon.CTSignatureSize)))
		falconKeyStore[f] = falconkey{nil, falconKeyStore[f].PrivateKey, falconKeyStore[f].PublicKey, &signature}
	}

	for f := 0; f < iterations; f++ {

		id := uuid.New().String()
		start := time.Now()
		recordType = "Falcon512_verify"
		falconKeyStore[f].PublicKey.Verify(*falconKeyStore[f].Sig, byteTest)
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
	}

	//SPHINCS+ 256

	for s := 0; s < iterations; s++ {
		id := uuid.New().String()
		start := time.Now()
		recordType = "SphincsPlus256Simple_keygen"
		privKey, pubKey := sphincs.Spx_keygen(parameters.MakeSphincsPlusSHA256128fSimple(true))
		elapsed := time.Since(start).Nanoseconds()
		serializedPK, _ := privKey.SerializeSK()
		serializedPubKey, _ := pubKey.SerializePK()
		records = append(records, newRecord(id, recordType, elapsed, strconv.Itoa(len(serializedPK)), strconv.Itoa(len(serializedPubKey)), "", ""))
		sphincsKeyStore[s] = sphincskey{nil, *privKey, *pubKey, nil}
	}

	for s := 0; s < iterations; s++ {

		id := uuid.New().String()
		start := time.Now()
		recordType = "SphincsPlus256Simple_sign"
		signature := sphincs.Spx_sign(parameters.MakeSphincsPlusSHA256128fSimple(true), byteTest, &sphincsKeyStore[s].PrivateKey)
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", strconv.Itoa(len(signature.R))))
		sphincsKeyStore[s] = sphincskey{nil, sphincsKeyStore[s].PrivateKey, sphincsKeyStore[s].PublicKey, signature}
	}

	for s := 0; s < iterations; s++ {

		id := uuid.New().String()
		start := time.Now()
		recordType = "SphincsPlus256Simple_verify"
		verifiedSig := sphincs.Spx_verify(parameters.MakeSphincsPlusSHA256128fSimple(true), byteTest, sphincsKeyStore[s].Sig, &sphincsKeyStore[s].PublicKey)
		_ = verifiedSig
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
	}

	for s := 0; s < iterations; s++ {
		id := uuid.New().String()
		start := time.Now()
		recordType = "SphincsPlus256Robust_keygen"
		privKey, pubKey := sphincs.Spx_keygen(parameters.MakeSphincsPlusSHA256128fRobust(true))
		elapsed := time.Since(start).Nanoseconds()
		serializedPK, _ := privKey.SerializeSK()
		serializedPubKey, _ := pubKey.SerializePK()
		records = append(records, newRecord(id, recordType, elapsed, strconv.Itoa(len(serializedPK)), strconv.Itoa(len(serializedPubKey)), "", ""))
		sphincsKeyStore[s] = sphincskey{nil, *privKey, *pubKey, nil}
	}

	for s := 0; s < iterations; s++ {

		id := uuid.New().String()
		start := time.Now()
		recordType = "SphincsPlus256Robust_sign"
		signature := sphincs.Spx_sign(parameters.MakeSphincsPlusSHA256128fRobust(true), byteTest, &sphincsKeyStore[s].PrivateKey)
		_ = signature
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", strconv.Itoa(len(signature.R))))
	}

	for s := 0; s < iterations; s++ {
		if sphincsKeyStore[s].Sig == nil {
			sphincsKeyStore[s].Sig = sphincs.Spx_sign(parameters.MakeSphincsPlusSHA256128fRobust(true), byteTest, &sphincsKeyStore[s].PrivateKey)
		}
		id := uuid.New().String()
		start := time.Now()
		recordType = "SphincsPlus256Robust_verify"
		verifiedSig := sphincs.Spx_verify(parameters.MakeSphincsPlusSHA256128fRobust(true), byteTest, sphincsKeyStore[s].Sig, &sphincsKeyStore[s].PublicKey)
		_ = verifiedSig
		elapsed := time.Since(start).Nanoseconds()
		records = append(records, newRecord(id, recordType, elapsed, "", "", "", ""))
	}

	csvCheck, errCheck := os.Open("logs/ecdsaLog.csv")
	if errCheck != nil {
		log.Printf("File not found: %s", errCheck)
	}
	defer csvCheck.Close()
	var headers = []string{"recordID", "recordType", "elapsedTime", "PrivateKeySize", "PublicKeySize", "hashString", "signatureSize"}
	filedata, errWrite := csv.NewReader(csvCheck).ReadAll()

	csvFile, errOpen := os.OpenFile("logs/ecdsaLog.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if errOpen != nil {
		log.Fatalf("failed creating file: %s", errOpen)
	}
	csvwriter := csv.NewWriter(csvFile)

	if len(filedata) == 0 {
		errWrite = csvwriter.Write(headers)
		if errWrite != nil {
			log.Fatalf("failed writing to file: %s", errWrite)
		}
	}
	log.Printf("Writing %d records to csv file", len(records))
	for _, recordAct := range records {
		var n int64 = recordAct.ElapsedTime
		errWrite := csvwriter.Write([]string{recordAct.ID, recordAct.Type, strconv.FormatInt(n, 10), recordAct.PrivateKeySize, recordAct.PublicKeySize, recordAct.hashString, recordAct.signatureSize})
		if errWrite != nil {
			log.Fatalf("failed writing to file: %s", errWrite)
		}
	}
	defer csvwriter.Flush()
	if err := csvwriter.Error(); err != nil {
		log.Fatal(err)
	}

}
