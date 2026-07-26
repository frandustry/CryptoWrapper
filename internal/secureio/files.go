// SPDX-License-Identifier: GPL-3.0-only

package secureio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// AtomicPath supplies a same-directory temporary path to writeFn and atomically
// installs it at destination after successful validation.
func AtomicPath(destination string, mode os.FileMode, force bool, writeFn func(string) error) error {
	if destination == "" || destination == "-" {
		return errors.New("a filesystem output path is required")
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	if info, statErr := os.Lstat(absolute); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink output: %s", destination)
		}
		if !force {
			return fmt.Errorf("output already exists: %s (use --force to replace it)", destination)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing non-regular output: %s", destination)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect output: %w", statErr)
	}

	directory := filepath.Dir(absolute)
	if info, statErr := os.Stat(directory); statErr != nil {
		return fmt.Errorf("inspect output directory: %w", statErr)
	} else if !info.IsDir() {
		return fmt.Errorf("output parent is not a directory: %s", directory)
	}

	file, err := os.CreateTemp(directory, ".cw-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	tempPath := file.Name()
	if closeErr := file.Close(); closeErr != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("close temporary output: %w", closeErr)
	}
	defer os.Remove(tempPath)
	if err := os.Chmod(tempPath, mode); err != nil {
		return fmt.Errorf("set temporary output permissions: %w", err)
	}
	if err := writeFn(tempPath); err != nil {
		return err
	}
	if err := os.Chmod(tempPath, mode); err != nil {
		return fmt.Errorf("set output permissions: %w", err)
	}
	if err := os.Rename(tempPath, absolute); err != nil {
		return fmt.Errorf("install output atomically: %w", err)
	}
	return nil
}

type OutputSpec struct {
	Path string
	Mode os.FileMode
}

// AtomicPair installs two related outputs as one operation. It is intended for
// private/public key pairs.
func AtomicPair(first, second OutputSpec, force bool, writeFn func(string, string) error) error {
	specs := []OutputSpec{first, second}
	destinations := make([]string, 2)
	temps := make([]string, 2)
	for index, spec := range specs {
		if spec.Path == "" || spec.Path == "-" {
			return errors.New("two filesystem output paths are required")
		}
		absolute, err := filepath.Abs(spec.Path)
		if err != nil {
			return fmt.Errorf("resolve output path: %w", err)
		}
		destinations[index] = absolute
		if info, statErr := os.Lstat(absolute); statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return fmt.Errorf("refusing non-regular output: %s", spec.Path)
			}
			if !force {
				return fmt.Errorf("output already exists: %s (use --force to replace it)", spec.Path)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("inspect output: %w", statErr)
		}
		file, err := os.CreateTemp(filepath.Dir(absolute), ".cw-pair-*.tmp")
		if err != nil {
			return fmt.Errorf("create temporary output: %w", err)
		}
		temps[index] = file.Name()
		if err := file.Close(); err != nil {
			return fmt.Errorf("close temporary output: %w", err)
		}
		defer os.Remove(temps[index])
	}
	if err := writeFn(temps[0], temps[1]); err != nil {
		return err
	}
	for index, spec := range specs {
		if err := os.Chmod(temps[index], spec.Mode); err != nil {
			return fmt.Errorf("set output permissions: %w", err)
		}
	}
	if err := os.Rename(temps[0], destinations[0]); err != nil {
		return fmt.Errorf("install first output: %w", err)
	}
	if err := os.Rename(temps[1], destinations[1]); err != nil {
		if !force {
			_ = os.Remove(destinations[0])
		}
		return fmt.Errorf("install second output: %w", err)
	}
	return nil
}
