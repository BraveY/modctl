/*
 *     Copyright 2025 The CNAI Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package build

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	modelspec "github.com/CloudNativeAI/model-spec/specs-go/v1"
	sha256 "github.com/minio/sha256-simd"
	godigest "github.com/opencontainers/go-digest"
	spec "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"

	buildconfig "github.com/CloudNativeAI/modctl/pkg/backend/build/config"
	"github.com/CloudNativeAI/modctl/pkg/backend/build/hooks"
	cc "github.com/CloudNativeAI/modctl/pkg/codec"
	"github.com/CloudNativeAI/modctl/pkg/storage"
	"github.com/CloudNativeAI/modctl/utils/nydusify"
)

// OutputType defines the type of output to generate.
type OutputType string

const (
	// OutputTypeLocal indicates that the output should be stored locally in modctl local storage.
	OutputTypeLocal OutputType = "local"
	// OutputTypeRemote indicates that the output should be pushed to a remote registry directly.
	OutputTypeRemote OutputType = "remote"
)

// Builder is an interface for building artifacts.
type Builder interface {
	// BuildLayer builds the layer blob from the given file path.
	BuildLayer(ctx context.Context, mediaType, workDir, path string, hooks hooks.Hooks) (ocispec.Descriptor, error)

	// BuildConfig builds the config blob of the artifact.
	BuildConfig(ctx context.Context, layers []ocispec.Descriptor, modelConfig *buildconfig.Model, hooks hooks.Hooks) (ocispec.Descriptor, error)

	// BuildManifest builds the manifest blob of the artifact.
	BuildManifest(ctx context.Context, layers []ocispec.Descriptor, config ocispec.Descriptor, annotations map[string]string, hooks hooks.Hooks) (ocispec.Descriptor, error)
}

type OutputStrategy interface {
	// OutputLayer outputs the layer blob to the storage (local or remote).
	OutputLayer(ctx context.Context, mediaType, relPath, digest string, size int64, reader io.Reader, hooks hooks.Hooks) (ocispec.Descriptor, error)

	// OutputConfig outputs the config blob to the storage (local or remote).
	OutputConfig(ctx context.Context, mediaType, digest string, size int64, reader io.Reader, hooks hooks.Hooks) (ocispec.Descriptor, error)

	// OutputManifest outputs the manifest blob to the storage (local or remote).
	OutputManifest(ctx context.Context, mediaType, digest string, size int64, reader io.Reader, hooks hooks.Hooks) (ocispec.Descriptor, error)
}

// NewBuilder creates a new builder instance.
func NewBuilder(outputType OutputType, store storage.Storage, repo, tag string, opts ...Option) (Builder, error) {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	var (
		strategy OutputStrategy
		err      error
	)
	switch outputType {
	case OutputTypeLocal:
		strategy, err = NewLocalOutput(cfg, store, repo, tag)
	case OutputTypeRemote:
		strategy, err = NewRemoteOutput(cfg, repo, tag)
	default:
		return nil, fmt.Errorf("unsupported output type: %s", outputType)
	}

	if err != nil {
		return nil, err
	}

	return &abstractBuilder{
		store:    store,
		repo:     repo,
		tag:      tag,
		strategy: strategy,
	}, nil
}

// abstractBuilder is an abstract implementation of the Builder interface.
type abstractBuilder struct {
	store storage.Storage
	repo  string
	tag   string
	// strategy is the output strategy used to output the blob.
	strategy OutputStrategy
}

func (ab *abstractBuilder) BuildLayer(ctx context.Context, mediaType, workDir, path string, hooks hooks.Hooks) (ocispec.Descriptor, error) {
	fmt.Printf("building layer: %s\n", path)
	info, err := os.Stat(path)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to get file info: %w", err)
	}

	if info.IsDir() {
		return ocispec.Descriptor{}, fmt.Errorf("%s is a directory and not supported yet", path)
	}

	workDirPath, err := filepath.Abs(workDir)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to get absolute path of workDir: %w", err)
	}

	// Gets the relative path of the file as annotation.
	//nolint:typecheck
	relPath, err := filepath.Rel(workDirPath, path)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to get relative path: %w", err)
	}

	codec, err := cc.New(cc.TypeFromMediaType(mediaType))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to create codec: %w", err)
	}

	// Encode the content by codec depends on the media type.
	reader, err := codec.Encode(path, workDirPath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to encode file: %w", err)
	}

	var wg sync.WaitGroup
	var crcDesc *ocispec.Descriptor
	if tarCode, ok := codec.(*cc.TarCodec); ok {
		fmt.Println("calculate crc32 per chunk")
		crcDesc = &ocispec.Descriptor{
			MediaType:   mediaType,
			Annotations: map[string]string{},
		}
		wg.Add(1)
		crcHandler := nydusify.NewCRCHandler()
		go func() {
			defer wg.Done()
			if err := crcHandler.Handle(context.Background(), tarCode.FileReader, crcDesc); err != nil {
				logrus.Error("failed to calculate crc32 per chunk")
				fmt.Println("failed to calculate crc32 per chunk")
			}
		}()
	}
	// Calculate the digest of the encoded content.
	hash := sha256.New()
	size, err := io.Copy(hash, reader)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to copy content to hash: %w", err)
	}

	digest := fmt.Sprintf("sha256:%x", hash.Sum(nil))
	wg.Wait()
	fmt.Printf("digest: %s\n", digest)

	// Seek the reader to the beginning if supported,
	// otherwise we needs to re-encode the content again.
	if seeker, ok := reader.(io.ReadSeeker); ok {
		fmt.Printf("seek reader to the beginning")
		if _, err := seeker.Seek(0, io.SeekStart); err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("failed to seek reader: %w", err)
		}
	} else {
		reader, err = codec.Encode(path, workDirPath)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("failed to encode file: %w", err)
		}
		if tarCode, ok := codec.(*cc.TarCodec); ok {
			go func() {
				io.Copy(io.Discard, tarCode.FileReader)
			}()
		}
	}

	desc, err := ab.strategy.OutputLayer(ctx, mediaType, relPath, digest, size, reader, hooks)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to output layer: %w", err)
	}
	if desc.Annotations != nil && crcDesc != nil && crcDesc.Annotations != nil {
		desc.Annotations[nydusify.CrcsKey] = crcDesc.Annotations[nydusify.CrcsKey]
	}
	return desc, nil
}

func (ab *abstractBuilder) BuildConfig(ctx context.Context, layers []ocispec.Descriptor, modelConfig *buildconfig.Model, hooks hooks.Hooks) (ocispec.Descriptor, error) {
	config, err := buildModelConfig(modelConfig, layers)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to build model config: %w", err)
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to marshal config: %w", err)
	}

	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(configJSON))
	return ab.strategy.OutputConfig(ctx, modelspec.MediaTypeModelConfig, digest, int64(len(configJSON)), bytes.NewReader(configJSON), hooks)
}

func (ab *abstractBuilder) BuildManifest(ctx context.Context, layers []ocispec.Descriptor, config ocispec.Descriptor, annotations map[string]string, hooks hooks.Hooks) (ocispec.Descriptor, error) {
	manifest := &ocispec.Manifest{
		Versioned: spec.Versioned{
			SchemaVersion: 2,
		},
		Annotations:  annotations,
		ArtifactType: modelspec.ArtifactTypeModelManifest,
		Config: ocispec.Descriptor{
			MediaType: config.MediaType,
			Digest:    config.Digest,
			Size:      config.Size,
		},
		MediaType: ocispec.MediaTypeImageManifest,
		Layers:    layers,
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to marshal manifest: %w", err)
	}

	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(manifestJSON))
	return ab.strategy.OutputManifest(ctx, manifest.MediaType, digest, int64(len(manifestJSON)), bytes.NewReader(manifestJSON), hooks)
}

// buildModelConfig builds the model config.
func buildModelConfig(modelConfig *buildconfig.Model, layers []ocispec.Descriptor) (*modelspec.Model, error) {
	if modelConfig == nil {
		return nil, fmt.Errorf("model config is nil")
	}

	config := modelspec.ModelConfig{
		Architecture: modelConfig.Architecture,
		Format:       modelConfig.Format,
		Precision:    modelConfig.Precision,
		Quantization: modelConfig.Quantization,
		ParamSize:    modelConfig.ParamSize,
	}

	createdAt := time.Now()
	descriptor := modelspec.ModelDescriptor{
		CreatedAt: &createdAt,
		Family:    modelConfig.Family,
		Name:      modelConfig.Name,
	}

	diffIDs := make([]godigest.Digest, 0, len(layers))
	for _, layer := range layers {
		diffIDs = append(diffIDs, layer.Digest)
	}

	fs := modelspec.ModelFS{
		Type:    "layers",
		DiffIDs: diffIDs,
	}

	return &modelspec.Model{
		Config:     config,
		Descriptor: descriptor,
		ModelFS:    fs,
	}, nil
}

func calculateCRC32PerChunk2(reader io.Reader, chunkSize int64) ([]uint32, error) {
	// 初始化 CRC32 表
	table := crc32.MakeTable(crc32.Castagnoli)

	// 存储每个块的 CRC32 校验和
	var crc32Results []uint32

	for {
		// 创建一个限制为 chunkSize 的 Reader
		limitedReader := io.LimitReader(reader, chunkSize)

		// 计算当前块的 CRC32 校验和
		hash := crc32.New(table)
		n, err := io.Copy(hash, limitedReader)
		// 检查是否到达 EOF 或发生错误
		if n == 0 || err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("failed to read data: %w", err)
		}

		// 如果读取到数据，保存 CRC32 校验和
		if n > 0 {
			crc32Results = append(crc32Results, hash.Sum32())
		}

	}
	return crc32Results, nil
}
