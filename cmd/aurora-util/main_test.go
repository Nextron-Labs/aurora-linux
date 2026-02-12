package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRelFromArchiveSubdir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		entry       string
		subdir      string
		wantRelPath string
		wantOK      bool
	}{
		{
			name:        "nested repository root",
			entry:       "SigmaHQ-sigma-abc123/rules/linux/process_creation/test.yml",
			subdir:      "rules/linux",
			wantRelPath: "process_creation/test.yml",
			wantOK:      true,
		},
		{
			name:        "direct rules path",
			entry:       "rules/linux/file_event/test.yml",
			subdir:      "rules/linux",
			wantRelPath: "file_event/test.yml",
			wantOK:      true,
		},
		{
			name:        "subdir root directory entry",
			entry:       "repo/rules/linux",
			subdir:      "rules/linux",
			wantRelPath: "",
			wantOK:      true,
		},
		{
			name:        "non-matching subdir",
			entry:       "repo/rules/windows/test.yml",
			subdir:      "rules/linux",
			wantRelPath: "",
			wantOK:      false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotRelPath, gotOK := relFromArchiveSubdir(tt.entry, tt.subdir)
			if gotOK != tt.wantOK {
				t.Fatalf("relFromArchiveSubdir() ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotRelPath != tt.wantRelPath {
				t.Fatalf("relFromArchiveSubdir() rel = %q, want %q", gotRelPath, tt.wantRelPath)
			}
		})
	}
}

func TestSelectAuroraAssetPrefersRenamedTarball(t *testing.T) {
	t.Parallel()

	assets := []githubReleaseAsset{
		{Name: "aurora-linux-v1.2.3-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.test/legacy.tgz"},
		{Name: "aurora-v1.2.3-linux-amd64.zip", BrowserDownloadURL: "https://example.test/new.zip"},
		{Name: "aurora-v1.2.3-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.test/new.tgz"},
	}

	asset, err := selectAuroraAsset(assets, "linux", "amd64", "")
	if err != nil {
		t.Fatalf("selectAuroraAsset() error = %v", err)
	}
	if asset.Name != "aurora-v1.2.3-linux-amd64.tar.gz" {
		t.Fatalf("selectAuroraAsset() picked %q", asset.Name)
	}
}

func TestSelectAuroraAssetFallsBackToLegacyName(t *testing.T) {
	t.Parallel()

	assets := []githubReleaseAsset{
		{Name: "aurora-linux-v1.2.3-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.test/legacy.tgz"},
	}

	asset, err := selectAuroraAsset(assets, "linux", "amd64", "")
	if err != nil {
		t.Fatalf("selectAuroraAsset() error = %v", err)
	}
	if asset.Name != "aurora-linux-v1.2.3-linux-amd64.tar.gz" {
		t.Fatalf("selectAuroraAsset() picked %q", asset.Name)
	}
}

func TestExtractBestBinaryFromTarGzPrefersAurora(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "release.tar.gz")
	outputPath := filepath.Join(tmpDir, "aurora")

	if err := writeTestTarGz(archivePath, map[string]string{
		"opt/aurora-linux/aurora-linux": "legacy-binary",
		"opt/aurora-linux/aurora":       "new-binary",
	}); err != nil {
		t.Fatalf("writeTestTarGz() error = %v", err)
	}

	entryName, err := extractBestBinaryFromTarGz(archivePath, outputPath, []string{"aurora", "aurora-linux"})
	if err != nil {
		t.Fatalf("extractBestBinaryFromTarGz() error = %v", err)
	}
	if entryName != "opt/aurora-linux/aurora" {
		t.Fatalf("extractBestBinaryFromTarGz() entry = %q", entryName)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content) != "new-binary" {
		t.Fatalf("output binary content = %q", string(content))
	}
}

func writeTestTarGz(archivePath string, files map[string]string) error {
	f, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gzw := gzip.NewWriter(f)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			return err
		}
	}

	return nil
}

func TestNormalizePprofBaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "root URL",
			input: "http://127.0.0.1:6060",
			want:  "http://127.0.0.1:6060",
		},
		{
			name:  "debug pprof path",
			input: "http://localhost:6060/debug/pprof/",
			want:  "http://localhost:6060",
		},
		{
			name:    "unsupported scheme",
			input:   "ftp://localhost:6060",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizePprofBaseURL(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizePprofBaseURL(%q) expected error", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizePprofBaseURL(%q) error = %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("normalizePprofBaseURL(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestRunCollectProfileDownloadsRequestedProfiles(t *testing.T) {
	t.Parallel()

	var cpuCalled atomic.Bool
	var heapCalled atomic.Bool
	var allocsCalled atomic.Bool
	var badSeconds atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/debug/pprof/profile":
			if got := r.URL.Query().Get("seconds"); got != "1" {
				badSeconds.Store(got)
			}
			cpuCalled.Store(true)
			_, _ = w.Write([]byte("cpu-profile"))
		case "/debug/pprof/heap":
			heapCalled.Store(true)
			_, _ = w.Write([]byte("heap-profile"))
		case "/debug/pprof/allocs":
			allocsCalled.Store(true)
			_, _ = w.Write([]byte("allocs-profile"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	outDir := t.TempDir()
	err := runCollectProfile(context.Background(), profileCaptureOptions{
		PprofURL:   server.URL,
		OutputDir:  outDir,
		CPUSeconds: 1,
		Heap:       true,
		Allocs:     true,
	})
	if err != nil {
		t.Fatalf("runCollectProfile() error = %v", err)
	}

	if got, ok := badSeconds.Load().(string); ok {
		t.Fatalf("profile seconds query = %q, want 1", got)
	}
	if !cpuCalled.Load() || !heapCalled.Load() || !allocsCalled.Load() {
		t.Fatalf(
			"expected all profile endpoints to be called (cpu=%v heap=%v allocs=%v)",
			cpuCalled.Load(),
			heapCalled.Load(),
			allocsCalled.Load(),
		)
	}

	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 3 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected 3 profile files, got %d (%s)", len(entries), strings.Join(names, ", "))
	}
}
