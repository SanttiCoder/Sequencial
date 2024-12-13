package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ripemd160"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	numGoroutines = 8
)

func hasRepeatedCharacters(key string) bool {
	if len(key) < 7 {
		return false
	}
	repeatCount := 1
	for i := 1; i < len(key); i++ {
		if key[i] == key[i-1] && key[i] != '0' {
			repeatCount++
			if repeatCount == 4 {
				return true
			}
		} else {
			repeatCount = 1
		}
	}
	return false
}

func GenerateAndSendKeys(pattern string, keysChan chan<- string, stopSignal chan struct{}) {
	chars := "0123456789abcdef"
	currentKey := []byte(strings.ReplaceAll(pattern, "x", "0"))

	for {
		select {
		case <-stopSignal:
			return
		default:
			if !hasRepeatedCharacters(string(currentKey)) {
				keysChan <- string(currentKey)
			}
			incremented := false
			for i := len(currentKey) - 1; i >= 0; i-- {
				if pattern[i] == 'x' {
					currentIndex := strings.IndexByte(chars, currentKey[i])
					if currentIndex < len(chars)-1 {
						currentKey[i] = chars[currentIndex+1]
						incremented = true
						break
					} else {
						currentKey[i] = '0'
					}
				}
			}
			if !incremented {
				return
			}
		}
	}
}

func SearchInKeys(wallets []string, keysChan <-chan string, stopSignal chan struct{}, startTime time.Time, keysChecked *int64, lastKeyTested *atomic.Value, mu *sync.Mutex) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopSignal:
			return
		case keyHex := <-keysChan:
			privKey := new(big.Int)
			privKey.SetString(keyHex, 16)
			atomic.AddInt64(keysChecked, 1)

			privKeyBytes := privKey.FillBytes(make([]byte, 32))
			pubKey := GeneratePublicKey(privKeyBytes)
			addressHash160 := Hash160(pubKey)
			addressHash160Hex := fmt.Sprintf("%x", addressHash160)

			if contains(wallets, addressHash160Hex) {
				wifKey := PrivateKeyToWIF(privKey)
				address := PublicKeyToAddress(pubKey)
				saveFoundKeyDetails(privKey, wifKey, address)
				close(stopSignal)
				return
			}

			// Proteja a leitura e escrita de lastKeyTested com o mutex
			mu.Lock()
			lastKeyTested.Store(keyHex)
			mu.Unlock()

		case <-ticker.C:
			mu.Lock()
			printProgress(startTime, keysChecked, lastKeyTested.Load().(string))  // Utilize lastKeyTested corretamente
			mu.Unlock()
		}
	}
}

func printProgress(startTime time.Time, keysChecked *int64, lastKeyTested string) {
	elapsed := time.Since(startTime)
	keysPerSecond := float64(atomic.LoadInt64(keysChecked)) / elapsed.Seconds()
	fmt.Printf("\rChaves/s: %06.0f | Última chave testada: %s", keysPerSecond, lastKeyTested)
}

func contains(wallets []string, addressHash160Hex string) bool {
	for _, wallet := range wallets {
		if wallet == addressHash160Hex {
			return true
		}
	}
	return false
}

func saveFoundKeyDetails(privKey *big.Int, wifKey, address string) {
	fmt.Println("\n-------------------CHAVE ENCONTRADA!!!!-------------------")
	fmt.Printf("Private key: %064x\n", privKey)
	fmt.Printf("WIF: %s\n", wifKey)
	fmt.Printf("Endereço: %s\n", address)

	file, err := os.OpenFile("found_keys.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Erro ao salvar chave encontrada: %v\n", err)
		return
	}
	defer file.Close()

	_, err = file.WriteString(fmt.Sprintf("\nPrivate key: %064x\nWIF: %s\nEndereço: %s\n", privKey, wifKey, address))
	if err != nil {
		fmt.Printf("Erro ao escrever chave encontrada: %v\n", err)
	}
}

var base58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
var curve = secp256k1.S256()

func GeneratePublicKey(privKeyBytes []byte) []byte {
	privKey := secp256k1.PrivKeyFromBytes(privKeyBytes)
	pubKey := privKey.PubKey()
	return pubKey.SerializeCompressed()
}

func PublicKeyToAddress(pubKey []byte) string {
	pubKeyHash := Hash160(pubKey)
	versionedPayload := append([]byte{0x00}, pubKeyHash...)
	return base58EncodeWithChecksum(versionedPayload)
}

func PrivateKeyToWIF(privKey *big.Int) string {
	privKeyBytes := privKey.FillBytes(make([]byte, 32))
	payload := append([]byte{0x80}, privKeyBytes...)
	payload = append(payload, 0x01)
	return base58EncodeWithChecksum(payload)
}

func AddressToHash160(address string) []byte {
	payload := base58Decode(address)
	return payload[1 : len(payload)-4]
}

func Hash160(data []byte) []byte {
	sha256Hash := sha256.Sum256(data)
	ripemd160Hasher := ripemd160.New()
	ripemd160Hasher.Write(sha256Hash[:])
	return ripemd160Hasher.Sum(nil)
}

func base58EncodeWithChecksum(payload []byte) string {
	checksum := checksum(payload)
	fullPayload := append(payload, checksum...)
	return base58Encode(fullPayload)
}

func base58Encode(input []byte) string {
	var result []byte
	x := new(big.Int).SetBytes(input)

	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := &big.Int{}

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}

	for _, b := range input {
		if b != 0x00 {
			break
		}
		result = append(result, base58Alphabet[0])
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

func base58Decode(input string) []byte {
	result := big.NewInt(0)
	base := big.NewInt(58)

	for _, char := range []byte(input) {
		value := bytes.IndexByte(base58Alphabet, char)
		if value == -1 {
			panic("Invalid Base58 character")
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(value)))
	}

	decoded := result.Bytes()

	leadingZeros := 0
	for _, char := range []byte(input) {
		if char != base58Alphabet[0] {
			break
		}
		leadingZeros++
	}

	return append(make([]byte, leadingZeros), decoded...)
}

func checksum(payload []byte) []byte {
	firstHash := sha256.Sum256(payload)
	secondHash := sha256.Sum256(firstHash[:])
	return secondHash[:4]
}

func main() {
	var address, pattern string

	fmt.Print("Endereço: ")
	fmt.Scanln(&address)

	fmt.Print("Padrão da chave: ")
	fmt.Scanln(&pattern)

	walletHash160 := fmt.Sprintf("%x", AddressToHash160(address))
	wallets := []string{walletHash160}

	startTime := time.Now()
	stopSignal := make(chan struct{})
	var wg sync.WaitGroup
	var keysChecked int64
	var mu sync.Mutex
	var lastKeyTested atomic.Value

	keysChan := make(chan string, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			SearchInKeys(wallets, keysChan, stopSignal, startTime, &keysChecked, &lastKeyTested, &mu)
		}()
	}

	go func() {
		GenerateAndSendKeys(pattern, keysChan, stopSignal)
		close(keysChan)
	}()

	wg.Wait()
}
