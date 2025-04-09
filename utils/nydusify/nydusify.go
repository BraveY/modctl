package nydusify

import (
	"context"
	"fmt"
	"hash/crc32"
	"io"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	ModelWeightMediaType  = "application/vnd.cnai.model.weight.v1.tar"
	ModelDatasetMediaType = "application/vnd.cnai.model.dataset.v1.tar"
	CrcsKey               = "org.opencontainers.image.crcs"
	DefaultFileChunkSize  = 4 * 1024 * 1024
)

var mediaTypeChunkSizeMap = map[string]int{
	ModelWeightMediaType:  64 * 1024 * 1024,
	ModelDatasetMediaType: 64 * 1024 * 1024,
}

type ModelHandler interface {
	Handle(ctx context.Context, r io.Reader, desc ocispec.Descriptor) error
}

type crcHandler struct {
	table *crc32.Table
}

func NewCRCHandler() *crcHandler {
	return &crcHandler{
		table: crc32.MakeTable(crc32.Castagnoli),
	}
}

// Read data from reader and checksum with CRC
func (h *crcHandler) Handle(ctx context.Context, r io.Reader, desc *ocispec.Descriptor) error {
	var crc32Results []uint32
	chunkSize := int64(DefaultFileChunkSize)
	if c, ok := mediaTypeChunkSizeMap[desc.MediaType]; ok {
		chunkSize = int64(c)
	}
	for {
		limitedReader := io.LimitReader(r, chunkSize)
		hash := crc32.New(h.table)
		n, err := io.Copy(hash, limitedReader)
		if n == 0 || err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("failed to read data: %w", err)
		}

		if n > 0 {
			crc32Results = append(crc32Results, hash.Sum32())
		}

	}

	if len(crc32Results) > 0 {
		hexCrcs := make([]string, len(crc32Results))
		for i, crc := range crc32Results {
			hexCrcs[i] = fmt.Sprintf("0x%x", crc)
		}
		crcs := strings.Join(hexCrcs, ",")
		desc.Annotations[CrcsKey] = crcs
		fmt.Printf("CRC32 values (hex): %s\n", crcs)
	}
	return nil
}
