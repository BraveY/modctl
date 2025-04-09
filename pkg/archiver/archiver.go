/*
 *     Copyright 2024 The CNAI Authors
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

package archiver

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

// Tar creates a tar archive of the specified path (file or directory)
// and returns the content as a stream. For individual files, it preserves
// the directory structure relative to the working directory.
func Tar(srcPath string, workDir string) (io.Reader, io.Reader, error) {
	logrus.Infof("Archiving %s", srcPath)
	pr, pw := io.Pipe()
	prOrig, pwOrig := io.Pipe()

	go func() {
		defer pw.Close()
		defer pwOrig.Close()
		tw := tar.NewWriter(pw)
		defer tw.Close()

		info, err := os.Stat(srcPath)
		if err != nil {
			pw.CloseWithError(fmt.Errorf("failed to stat source path: %w", err))
			pwOrig.CloseWithError(fmt.Errorf("failed to stat source path: %w", err))
			return
		}

		// Handle directories and files differently.
		if info.IsDir() {
			// For directories, walk through and add all files/subdirs.
			err = filepath.Walk(srcPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				// Create a relative path for the tar file header.
				relPath, err := filepath.Rel(workDir, path)
				if err != nil {
					return fmt.Errorf("failed to get relative path: %w", err)
				}

				header, err := tar.FileInfoHeader(info, "")
				if err != nil {
					return fmt.Errorf("failed to create tar header: %w", err)
				}

				// Set the header name to preserve directory structure.
				header.Name = relPath
				if err := tw.WriteHeader(header); err != nil {
					return fmt.Errorf("failed to write header: %w", err)
				}

				if !info.IsDir() {
					file, err := os.Open(path)
					if err != nil {
						return fmt.Errorf("failed to open file %s: %w", path, err)
					}
					defer file.Close()

					// Use TeeReader to copy file content to both original and tar writer
					tee := io.TeeReader(file, pwOrig)
					if _, err := io.Copy(tw, tee); err != nil {
						return fmt.Errorf("failed to write file %s to tar: %w", path, err)
					}
				}

				return nil
			})

			if err != nil {
				pw.CloseWithError(fmt.Errorf("failed to walk directory: %w", err))
				pwOrig.CloseWithError(fmt.Errorf("failed to walk directory: %w", err))
				return
			}
		} else {
			// For a single file, include the directory structure.
			file, err := os.Open(srcPath)
			if err != nil {
				pw.CloseWithError(fmt.Errorf("failed to open file: %w", err))
				pwOrig.CloseWithError(fmt.Errorf("failed to open file: %w", err))
				return
			}
			defer file.Close()

			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				pw.CloseWithError(fmt.Errorf("failed to create tar header: %w", err))
				pwOrig.CloseWithError(fmt.Errorf("failed to create tar header: %w", err))
				return
			}

			// Use relative path as the header name to preserve directory structure
			// This keeps the directory structure as part of the file path in the tar.
			relPath, err := filepath.Rel(workDir, srcPath)
			if err != nil {
				pw.CloseWithError(fmt.Errorf("failed to get relative path: %w", err))
				pwOrig.CloseWithError(fmt.Errorf("failed to get relative path: %w", err))
				return
			}

			// Use the relative path (including directories) as the header name.
			header.Name = relPath
			if err := tw.WriteHeader(header); err != nil {
				pw.CloseWithError(fmt.Errorf("failed to write header: %w", err))
				pwOrig.CloseWithError(fmt.Errorf("failed to write header: %w", err))
				return
			}

			// Use TeeReader to copy file content to both original and tar writer
			tee := io.TeeReader(file, pwOrig)
			if _, err := io.Copy(tw, tee); err != nil {
				pw.CloseWithError(fmt.Errorf("failed to copy file to tar: %w", err))
				pwOrig.CloseWithError(fmt.Errorf("failed to copy file to tar: %w", err))
				return
			}
		}
	}()

	return pr, prOrig, nil
}

// Untar extracts the contents of a tar archive from the provided reader
// to the specified destination path.
func Untar(reader io.Reader, destPath string) error {
	tarReader := tar.NewReader(reader)

	// Ensure destination directory exists.
	if err := os.MkdirAll(destPath, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading tar: %w", err)
		}

		// Sanitize file paths to prevent directory traversal.
		cleanPath := filepath.Clean(header.Name)
		if strings.Contains(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") || strings.HasPrefix(cleanPath, ":\\") {
			return fmt.Errorf("tar file contains invalid path: %s", cleanPath)
		}

		targetPath := filepath.Join(destPath, cleanPath)

		// Create directories for all path components.
		dirPath := filepath.Dir(targetPath)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dirPath, err)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}

		case tar.TypeReg:
			file, err := os.OpenFile(
				targetPath,
				os.O_CREATE|os.O_RDWR|os.O_TRUNC,
				os.FileMode(header.Mode),
			)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return fmt.Errorf("failed to write to file %s: %w", targetPath, err)
			}
			file.Close()

		case tar.TypeSymlink:
			if isRel(header.Linkname, destPath) && isRel(header.Name, destPath) {
				if err := os.Symlink(header.Linkname, targetPath); err != nil {
					return fmt.Errorf("failed to create symlink %s -> %s: %w", targetPath, header.Linkname, err)
				}
			} else {
				return fmt.Errorf("symlink %s -> %s points outside of destination directory", targetPath, header.Linkname)
			}

		default:
			// Skip other types.
			continue
		}
	}

	return nil
}

// isRel checks if the candidate path is within the target directory after resolving symbolic links.
func isRel(candidate, target string) bool {
	if filepath.IsAbs(candidate) {
		return false
	}

	realpath, err := filepath.EvalSymlinks(filepath.Join(target, candidate))
	if err != nil {
		return false
	}

	relpath, err := filepath.Rel(target, realpath)
	return err == nil && !strings.HasPrefix(filepath.Clean(relpath), "..")
}
