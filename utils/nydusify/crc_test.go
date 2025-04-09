package nydusify

import (
	"fmt"
	"hash/crc32"
	"testing"

	"github.com/stretchr/testify/assert"
)

func crc32Castagnoli(data []byte) uint32 {
	table := crc32.MakeTable(crc32.Castagnoli)
	crcHash := crc32.New(table)
	crcHash.Write(data)
	return crcHash.Sum32()
}

func TestCrc32Iscsi(t *testing.T) {
	data := []byte("123456789")
	crc32 := crc32Castagnoli(data)
	fmt.Printf("CRC_32_CASTAGNOLI: %x\n", crc32)
	assert.Equal(t, uint32(0xe3069283), crc32)
}
