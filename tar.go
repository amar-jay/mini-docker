package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func untar(tarball, target string) error {
	// Open the tarball file
	file, err := os.Open(tarball)
	if err != nil {
		return fmt.Errorf("opening tarball: %w", err)
	}
	defer file.Close()

	var tarReader *tar.Reader

	// Detect if the file is gzipped by extension
	if strings.HasSuffix(tarball, ".gz") || strings.HasSuffix(tarball, ".tgz") {
		gzr, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("creating gzip reader: %w", err)
		}
		defer gzr.Close()
		tarReader = tar.NewReader(gzr)
	} else {
		// Plain tar file
		tarReader = tar.NewReader(file)
	}

	hardLinks := make(map[string]string)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("reading tar entry: %w", err)
		}

		path := filepath.Join(target, header.Name)
		info := header.FileInfo()

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, info.Mode()); err != nil {
				return fmt.Errorf("mkdir %s: %w", path, err)
			}

		case tar.TypeLink:
			// Defer creating hard links until after all files extracted
			linkPath := filepath.Join(target, header.Linkname)
			hardLinks[path] = linkPath

		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, path); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("symlink %s -> %s: %w", path, header.Linkname, err)
				}
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return fmt.Errorf("mkdir for file %s: %w", path, err)
			}
			outFile, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
			if err != nil {
				return fmt.Errorf("create file %s: %w", path, err)
			}
			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("copy file %s: %w", path, err)
			}
			outFile.Close()

		default:
			log.Printf("Skipping unsupported file type %c in %s\n", header.Typeflag, path)
		}
	}

	// Create hard links after extraction
	for link, target := range hardLinks {
		if err := os.Link(target, link); err != nil {
			return fmt.Errorf("creating hard link %s -> %s: %w", link, target, err)
		}
	}

	return nil
}
