package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"os"
	"strings"
	"time"
)

func toBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	shifts := [8]uint16{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func toUint32(bytes []byte) uint32 {
	return (uint32(bytes[0]) << 24) + (uint32(bytes[1]) << 16) +
		(uint32(bytes[2]) << 8) + uint32(bytes[3])
}

//结合用户身上有的key.和时间戳的(因为数据是30秒更新一次,所以是取时间的epochSecond/30.得到的值,所以可以有30秒的误差.
func oneTimePassword(key []byte, value []byte) uint32 {
	// sign the value using HMAC-SHA1
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(value)
	hash := hmacSha1.Sum(nil)
	fmt.Printf("hash:%#v\n",hash)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	//oxoF代表的是1111.这样运算出来与的结果最大值是15.而hash的运算结果是160位(20个byte).
	// 也就是长度为20 byte slice.最大15,加上后面的+4.返回最大取的是15-19.最小是0.所以一定不会出现outofbound的情况.
	offset := hash[len(hash)-1] & 0x0F
	fmt.Printf("offset:%#v\n",offset)

	fmt.Printf("offset:%d,offset+4:%d\n",offset,offset+4)
	// get a 32-bit (4-byte) chunk from the hash starting at offset
	//通过offset-offset+4.得到一个永不越界的长度为4的byte slice(32位)
	hashParts := hash[offset : offset+4]
	fmt.Printf("hashParts:%#v\n",hashParts)

	// ignore the most significant bit as per RFC 4226
	//0x7F是127.也就是最高位为0，其他全1.跟hashParts里的第一个byte做与.这时候得到的最大数据则是127.
	//这里是为了去掉最高位的数据.不然转到uint32就可能越界.
	//为什么要转到uint32.参考RFC4226
	hashParts[0] = hashParts[0] & 0x7F
	fmt.Printf("hashParts[0]:%#v\n",hashParts[0])
	number := toUint32(hashParts)
	fmt.Println("number:",number)
	// size to 6 digits
	// one million is the first number with 7 digits so the remainder
	// of the division will always return < 7 digits
	pwd := number % 1000000
	fmt.Println("pwd:",pwd)
	return pwd
}

// all []byte in this program are treated as Big Endian
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "must specify key to use")
		os.Exit(1)
	}

	input := os.Args[1]

	// decode the key from the first argument
	inputNoSpaces := strings.Replace(input, " ", "", -1)
	inputNoSpacesUpper := strings.ToUpper(inputNoSpaces)
	key, err := base32.StdEncoding.DecodeString(inputNoSpacesUpper)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// generate a one-time password using the time at 30-second intervals
	epochSeconds := time.Now().Unix()
	pwd := oneTimePassword(key, toBytes(epochSeconds/30))

	secondsRemaining := 30 - (epochSeconds % 30)
	fmt.Printf("%06d (%d second(s) remaining)\n", pwd, secondsRemaining)
}
