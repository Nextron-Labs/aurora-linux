package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultHTTPTimeout = 3 * time.Minute
)

var version = "dev"

type githubRelease struct {
	TagName    string               `json:"tag_name"`
	Name       string               `json:"name"`
	TarballURL string               `json:"tarball_url"`
	ZipballURL string               `json:"zipball_url"`
	Assets     []githubReleaseAsset `json:"assets"`
}

type githubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type signaturesOptions struct {
	Repo         string
	Version      string
	RulesDir     string
	SourceSubdir string
	AssetName    string
	GitHubToken  string
	DryRun       bool
}

type upgradeOptions struct {
	Repo        string
	Version     string
	InstallPath string
	TargetOS    string
	TargetArch  string
	AssetName   string
	GitHubToken string
	DryRun      bool
}

type profileCaptureOptions struct {
	PprofURL   string
	OutputDir  string
	CPUSeconds int
	Heap       bool
	Allocs     bool
	Timeout    time.Duration
}

func main() {
	rootCmd := &cobra.Command{
		Use:     "aurora-util",
		Short:   "Aurora Linux update utility",
		Version: version,
	}

	var sigOpts signaturesOptions
	sigCmd := &cobra.Command{
		Use:   "update-signatures",
		Short: "Update Sigma Linux signatures from GitHub releases",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return runUpdateSignatures(ctx, sigOpts)
		},
	}
	sigCmd.Flags().StringVar(&sigOpts.Repo, "repo", "SigmaHQ/sigma", "GitHub repository in owner/repo format")
	sigCmd.Flags().StringVar(&sigOpts.Version, "version", "latest", "Release tag to fetch (or \"latest\")")
	sigCmd.Flags().StringVar(&sigOpts.RulesDir, "rules-dir", "/opt/aurora-linux/sigma-rules/rules/linux", "Destination directory for Linux Sigma rules")
	sigCmd.Flags().StringVar(&sigOpts.SourceSubdir, "source-subdir", "rules/linux", "Subdirectory inside the release archive to install")
	sigCmd.Flags().StringVar(&sigOpts.AssetName, "asset", "", "Optional explicit release asset name")
	sigCmd.Flags().StringVar(&sigOpts.GitHubToken, "github-token", "", "Optional GitHub API token (defaults to GITHUB_TOKEN env)")
	sigCmd.Flags().BoolVar(&sigOpts.DryRun, "dry-run", false, "Print actions without writing changes")

	var upOpts upgradeOptions
	upgradeCmd := &cobra.Command{
		Use:   "upgrade-aurora",
		Short: "Upgrade the aurora binary from Aurora-Linux GitHub releases",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return runUpgradeAurora(ctx, upOpts)
		},
	}
	upgradeCmd.Flags().StringVar(&upOpts.Repo, "repo", "Nextron-Labs/aurora-linux", "GitHub repository in owner/repo format")
	upgradeCmd.Flags().StringVar(&upOpts.Version, "version", "latest", "Release tag to fetch (or \"latest\")")
	upgradeCmd.Flags().StringVar(&upOpts.InstallPath, "install-path", "/opt/aurora-linux/aurora", "Destination path for the aurora binary")
	upgradeCmd.Flags().StringVar(&upOpts.TargetOS, "os", runtime.GOOS, "Target operating system used for release asset matching")
	upgradeCmd.Flags().StringVar(&upOpts.TargetArch, "arch", runtime.GOARCH, "Target architecture used for release asset matching")
	upgradeCmd.Flags().StringVar(&upOpts.AssetName, "asset", "", "Optional explicit release asset name")
	upgradeCmd.Flags().StringVar(&upOpts.GitHubToken, "github-token", "", "Optional GitHub API token (defaults to GITHUB_TOKEN env)")
	upgradeCmd.Flags().BoolVar(&upOpts.DryRun, "dry-run", false, "Print actions without writing changes")

	var profileOpts profileCaptureOptions
	profileCmd := &cobra.Command{
		Use:   "collect-profile",
		Short: "Collect pprof CPU/heap profiles from a running Aurora agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			return runCollectProfile(ctx, profileOpts)
		},
	}
	profileCmd.Flags().StringVar(&profileOpts.PprofURL, "pprof-url", "http://127.0.0.1:6060", "Base URL of aurora pprof endpoint")
	profileCmd.Flags().StringVar(&profileOpts.OutputDir, "output-dir", ".", "Directory where profiles are written")
	profileCmd.Flags().IntVar(&profileOpts.CPUSeconds, "cpu-seconds", 30, "CPU profile duration in seconds (0 disables CPU profile)")
	profileCmd.Flags().BoolVar(&profileOpts.Heap, "heap", true, "Collect heap profile (/debug/pprof/heap?gc=1)")
	profileCmd.Flags().BoolVar(&profileOpts.Allocs, "allocs", false, "Collect allocs profile (/debug/pprof/allocs?gc=1)")
	profileCmd.Flags().DurationVar(&profileOpts.Timeout, "timeout", 0, "HTTP timeout (default: derived from cpu-seconds)")

	rootCmd.AddCommand(sigCmd, upgradeCmd, profileCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runUpdateSignatures(ctx context.Context, opts signaturesOptions) error {
	client := &http.Client{Timeout: defaultHTTPTimeout}

	release, err := fetchRelease(ctx, client, opts.Repo, opts.Version, resolveToken(opts.GitHubToken))
	if err != nil {
		return err
	}

	archiveURL, archiveLabel, err := selectSignatureArchive(release, opts.AssetName)
	if err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "aurora-util-sigma-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, "sigma-release"+archiveSuffix(archiveLabel))
	if err := downloadFile(ctx, client, archiveURL, resolveToken(opts.GitHubToken), archivePath); err != nil {
		return err
	}

	stagedRules := filepath.Join(tmpDir, "rules-linux")
	filesWritten, err := extractSubdirFromArchive(archivePath, opts.SourceSubdir, stagedRules)
	if err != nil {
		return err
	}

	fmt.Printf("Prepared %d rule files from %s (%s)\n", filesWritten, release.TagName, archiveLabel)
	if opts.DryRun {
		fmt.Printf("[dry-run] Would replace %s\n", opts.RulesDir)
		return nil
	}

	backupPath, err := replaceDirectoryWithBackup(stagedRules, opts.RulesDir)
	if err != nil {
		return err
	}

	metadataPath, metadataErr := writeSignatureSourceMetadata(opts.RulesDir, opts.Repo, release, archiveURL)
	if metadataErr != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to write SOURCE metadata: %v\n", metadataErr)
	}

	fmt.Printf("Updated Sigma rules in %s\n", opts.RulesDir)
	if backupPath != "" {
		fmt.Printf("Previous rules backup: %s\n", backupPath)
	}
	if metadataPath != "" {
		fmt.Printf("Updated metadata: %s\n", metadataPath)
	}

	return nil
}

func runUpgradeAurora(ctx context.Context, opts upgradeOptions) error {
	client := &http.Client{Timeout: defaultHTTPTimeout}

	release, err := fetchRelease(ctx, client, opts.Repo, opts.Version, resolveToken(opts.GitHubToken))
	if err != nil {
		return err
	}

	asset, err := selectAuroraAsset(release.Assets, opts.TargetOS, opts.TargetArch, opts.AssetName)
	if err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "aurora-util-upgrade-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, "aurora-release"+archiveSuffix(asset.Name))
	if err := downloadFile(ctx, client, asset.BrowserDownloadURL, resolveToken(opts.GitHubToken), archivePath); err != nil {
		return err
	}

	stagedBinary := filepath.Join(tmpDir, "aurora")
	entryName, err := extractBestBinaryFromArchive(archivePath, stagedBinary, []string{"aurora", "aurora-linux"})
	if err != nil {
		return err
	}

	fmt.Printf("Prepared binary from release %s asset %s (%s)\n", release.TagName, asset.Name, entryName)
	if opts.DryRun {
		fmt.Printf("[dry-run] Would install binary to %s\n", opts.InstallPath)
		return nil
	}

	backupPath, err := installBinaryWithBackup(stagedBinary, opts.InstallPath)
	if err != nil {
		return err
	}

	fmt.Printf("Installed aurora binary to %s\n", opts.InstallPath)
	if backupPath != "" {
		fmt.Printf("Previous binary backup: %s\n", backupPath)
	}
	return nil
}

func runCollectProfile(ctx context.Context, opts profileCaptureOptions) error {
	baseURL, err := normalizePprofBaseURL(opts.PprofURL)
	if err != nil {
		return err
	}
	if opts.CPUSeconds < 0 {
		return fmt.Errorf("--cpu-seconds must be >= 0, got %d", opts.CPUSeconds)
	}
	if !opts.Heap && !opts.Allocs && opts.CPUSeconds == 0 {
		return errors.New("nothing to collect: enable --heap/--allocs or set --cpu-seconds > 0")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
		if opts.CPUSeconds > 0 {
			timeout = time.Duration(opts.CPUSeconds+15) * time.Second
		}
	}
	client := &http.Client{Timeout: timeout}

	outDir := strings.TrimSpace(opts.OutputDir)
	if outDir == "" {
		return errors.New("--output-dir cannot be empty")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating output directory %q: %w", outDir, err)
	}

	ts := time.Now().UTC().Format("20060102T150405Z")
	written := make([]string, 0, 3)

	if opts.CPUSeconds > 0 {
		cpuURL := fmt.Sprintf("%s/debug/pprof/profile?seconds=%d", baseURL, opts.CPUSeconds)
		cpuPath := filepath.Join(outDir, fmt.Sprintf("aurora-cpu-%ds-%s.pprof", opts.CPUSeconds, ts))
		if err := downloadFile(ctx, client, cpuURL, "", cpuPath); err != nil {
			return err
		}
		written = append(written, cpuPath)
	}

	if opts.Heap {
		heapURL := fmt.Sprintf("%s/debug/pprof/heap?gc=1", baseURL)
		heapPath := filepath.Join(outDir, fmt.Sprintf("aurora-heap-%s.pprof", ts))
		if err := downloadFile(ctx, client, heapURL, "", heapPath); err != nil {
			return err
		}
		written = append(written, heapPath)
	}

	if opts.Allocs {
		allocsURL := fmt.Sprintf("%s/debug/pprof/allocs?gc=1", baseURL)
		allocsPath := filepath.Join(outDir, fmt.Sprintf("aurora-allocs-%s.pprof", ts))
		if err := downloadFile(ctx, client, allocsURL, "", allocsPath); err != nil {
			return err
		}
		written = append(written, allocsPath)
	}

	for _, profilePath := range written {
		fmt.Printf("Wrote profile: %s\n", profilePath)
	}
	return nil
}

func normalizePprofBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("--pprof-url cannot be empty")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid --pprof-url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("--pprof-url must use http or https (got %q)", raw)
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", fmt.Errorf("--pprof-url must include host:port (got %q)", raw)
	}

	cleanPath := strings.TrimSuffix(u.Path, "/")
	if strings.HasSuffix(cleanPath, "/debug/pprof") {
		cleanPath = strings.TrimSuffix(cleanPath, "/debug/pprof")
	}
	if cleanPath == "/debug/pprof" {
		cleanPath = ""
	}
	u.Path = cleanPath
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""

	return strings.TrimSuffix(u.String(), "/"), nil
}

func fetchRelease(ctx context.Context, client *http.Client, repo, version, token string) (githubRelease, error) {
	if !validRepo(repo) {
		return githubRelease{}, fmt.Errorf("invalid --repo value %q, expected owner/repo", repo)
	}

	endpoint := releaseEndpoint(repo, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return githubRelease{}, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "aurora-util")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return githubRelease{}, fmt.Errorf("fetching release metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyPreview, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return githubRelease{}, fmt.Errorf(
			"release metadata request failed: %s (%s)",
			resp.Status,
			strings.TrimSpace(string(bodyPreview)),
		)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return githubRelease{}, fmt.Errorf("decoding release metadata: %w", err)
	}
	if release.TagName == "" {
		return githubRelease{}, errors.New("release metadata missing tag_name")
	}
	return release, nil
}

func releaseEndpoint(repo, version string) string {
	base := "https://api.github.com/repos/" + repo + "/releases"
	if strings.EqualFold(strings.TrimSpace(version), "latest") || strings.TrimSpace(version) == "" {
		return base + "/latest"
	}
	tag := strings.TrimSpace(version)
	tag = strings.TrimPrefix(tag, "refs/tags/")
	return base + "/tags/" + url.PathEscape(tag)
}

func selectSignatureArchive(release githubRelease, explicitAsset string) (string, string, error) {
	if explicitAsset != "" {
		for _, asset := range release.Assets {
			if asset.Name == explicitAsset {
				if asset.BrowserDownloadURL == "" {
					return "", "", fmt.Errorf("asset %q has no download URL", explicitAsset)
				}
				return asset.BrowserDownloadURL, asset.Name, nil
			}
		}
		return "", "", fmt.Errorf("asset %q not found in release %s", explicitAsset, release.TagName)
	}

	for _, asset := range release.Assets {
		name := strings.ToLower(asset.Name)
		if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") || strings.HasSuffix(name, ".zip") {
			if asset.BrowserDownloadURL != "" {
				return asset.BrowserDownloadURL, asset.Name, nil
			}
		}
	}

	if release.TarballURL != "" {
		return release.TarballURL, "tarball_url", nil
	}
	if release.ZipballURL != "" {
		return release.ZipballURL, "zipball_url", nil
	}

	return "", "", fmt.Errorf("release %s has no downloadable archive", release.TagName)
}

func selectAuroraAsset(assets []githubReleaseAsset, targetOS, targetArch, explicitAsset string) (githubReleaseAsset, error) {
	if explicitAsset != "" {
		for _, asset := range assets {
			if asset.Name == explicitAsset {
				if asset.BrowserDownloadURL == "" {
					return githubReleaseAsset{}, fmt.Errorf("asset %q has no download URL", explicitAsset)
				}
				return asset, nil
			}
		}
		return githubReleaseAsset{}, fmt.Errorf("asset %q not found in release", explicitAsset)
	}

	osAliases := normalizeAliases(targetOS, map[string][]string{
		"linux":   {"linux"},
		"darwin":  {"darwin", "macos", "osx"},
		"windows": {"windows", "win"},
	})
	archAliases := normalizeAliases(targetArch, map[string][]string{
		"amd64": {"amd64", "x86_64"},
		"386":   {"386", "i386", "x86"},
		"arm64": {"arm64", "aarch64"},
		"arm":   {"armv7", "arm"},
	})

	type candidate struct {
		asset githubReleaseAsset
		score int
	}
	candidates := make([]candidate, 0, len(assets))
	for _, asset := range assets {
		nameLower := strings.ToLower(asset.Name)
		if !isArchiveName(nameLower) {
			continue
		}
		if !containsAny(nameLower, osAliases) || !containsAny(nameLower, archAliases) {
			continue
		}

		score := 0
		if strings.Contains(nameLower, "aurora-linux") {
			score += 1
		}
		if strings.HasSuffix(nameLower, ".zip") {
			score += 1
		}

		candidates = append(candidates, candidate{asset: asset, score: score})
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score < candidates[j].score
		}
		return candidates[i].asset.Name < candidates[j].asset.Name
	})
	if len(candidates) > 0 {
		return candidates[0].asset, nil
	}

	for _, asset := range assets {
		nameLower := strings.ToLower(asset.Name)
		if isArchiveName(nameLower) && strings.Contains(nameLower, "aurora") {
			return asset, nil
		}
	}

	available := make([]string, 0, len(assets))
	for _, asset := range assets {
		available = append(available, asset.Name)
	}
	sort.Strings(available)
	return githubReleaseAsset{}, fmt.Errorf(
		"no matching release asset for os=%s arch=%s; available assets: %s",
		targetOS,
		targetArch,
		strings.Join(available, ", "),
	)
}

func downloadFile(ctx context.Context, client *http.Client, downloadURL, token, outputPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return fmt.Errorf("creating download request: %w", err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "aurora-util")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyPreview, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf(
			"download failed for %s: %s (%s)",
			downloadURL,
			resp.Status,
			strings.TrimSpace(string(bodyPreview)),
		)
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}
	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("creating output file %q: %w", outputPath, err)
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return fmt.Errorf("writing output file %q: %w", outputPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing output file %q: %w", outputPath, err)
	}
	return nil
}

func extractSubdirFromArchive(archivePath, sourceSubdir, destinationDir string) (int, error) {
	format, err := detectArchiveFormat(archivePath)
	if err != nil {
		return 0, err
	}

	switch format {
	case "zip":
		return extractSubdirFromZip(archivePath, sourceSubdir, destinationDir)
	case "tar.gz":
		return extractSubdirFromTarGz(archivePath, sourceSubdir, destinationDir)
	default:
		return 0, fmt.Errorf("unsupported archive format for %s", archivePath)
	}
}

func extractSubdirFromTarGz(archivePath, sourceSubdir, destinationDir string) (int, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return 0, fmt.Errorf("opening archive %q: %w", archivePath, err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("opening gzip stream: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	written := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("reading tar archive: %w", err)
		}

		rel, ok := relFromArchiveSubdir(hdr.Name, sourceSubdir)
		if !ok || rel == "" {
			continue
		}

		targetPath, err := safeJoin(destinationDir, filepath.FromSlash(rel))
		if err != nil {
			return 0, err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return 0, fmt.Errorf("creating directory %q: %w", targetPath, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return 0, fmt.Errorf("creating parent directory for %q: %w", targetPath, err)
			}
			mode := hdr.FileInfo().Mode().Perm()
			if mode == 0 {
				mode = 0o644
			}
			if err := writeReaderToFile(targetPath, tr, mode); err != nil {
				return 0, err
			}
			written++
		}
	}

	if written == 0 {
		return 0, fmt.Errorf("no files found under %q in archive", sourceSubdir)
	}
	return written, nil
}

func extractSubdirFromZip(archivePath, sourceSubdir, destinationDir string) (int, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return 0, fmt.Errorf("opening zip archive %q: %w", archivePath, err)
	}
	defer zr.Close()

	written := 0
	for _, file := range zr.File {
		rel, ok := relFromArchiveSubdir(file.Name, sourceSubdir)
		if !ok || rel == "" {
			continue
		}

		targetPath, err := safeJoin(destinationDir, filepath.FromSlash(rel))
		if err != nil {
			return 0, err
		}

		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return 0, fmt.Errorf("creating directory %q: %w", targetPath, err)
			}
			continue
		}

		rc, err := file.Open()
		if err != nil {
			return 0, fmt.Errorf("opening zip entry %q: %w", file.Name, err)
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			_ = rc.Close()
			return 0, fmt.Errorf("creating parent directory for %q: %w", targetPath, err)
		}
		mode := file.Mode().Perm()
		if mode == 0 {
			mode = 0o644
		}
		if err := writeReaderToFile(targetPath, rc, mode); err != nil {
			_ = rc.Close()
			return 0, err
		}
		if err := rc.Close(); err != nil {
			return 0, fmt.Errorf("closing zip entry %q: %w", file.Name, err)
		}
		written++
	}

	if written == 0 {
		return 0, fmt.Errorf("no files found under %q in archive", sourceSubdir)
	}
	return written, nil
}

func extractBestBinaryFromArchive(archivePath, outputPath string, preferredNames []string) (string, error) {
	format, err := detectArchiveFormat(archivePath)
	if err != nil {
		return "", err
	}

	switch format {
	case "zip":
		return extractBestBinaryFromZip(archivePath, outputPath, preferredNames)
	case "tar.gz":
		return extractBestBinaryFromTarGz(archivePath, outputPath, preferredNames)
	default:
		return "", fmt.Errorf("unsupported archive format for %s", archivePath)
	}
}

func extractBestBinaryFromTarGz(archivePath, outputPath string, preferredNames []string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("opening archive %q: %w", archivePath, err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("opening gzip stream: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	bestRank := len(preferredNames) + 1
	bestName := ""
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("reading tar archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}

		rank := preferredNameRank(path.Base(hdr.Name), preferredNames)
		if rank < 0 || rank >= bestRank {
			continue
		}

		if err := writeReaderToFile(outputPath, tr, 0o755); err != nil {
			return "", err
		}
		bestRank = rank
		bestName = hdr.Name
		if rank == 0 {
			break
		}
	}

	if bestName == "" {
		return "", fmt.Errorf("no binary named %s found in archive", strings.Join(preferredNames, ", "))
	}
	return bestName, nil
}

func extractBestBinaryFromZip(archivePath, outputPath string, preferredNames []string) (string, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("opening zip archive %q: %w", archivePath, err)
	}
	defer zr.Close()

	bestRank := len(preferredNames) + 1
	bestName := ""
	for _, file := range zr.File {
		if file.FileInfo().IsDir() {
			continue
		}
		rank := preferredNameRank(path.Base(file.Name), preferredNames)
		if rank < 0 || rank >= bestRank {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			return "", fmt.Errorf("opening zip entry %q: %w", file.Name, err)
		}
		if err := writeReaderToFile(outputPath, rc, 0o755); err != nil {
			_ = rc.Close()
			return "", err
		}
		if err := rc.Close(); err != nil {
			return "", fmt.Errorf("closing zip entry %q: %w", file.Name, err)
		}

		bestRank = rank
		bestName = file.Name
		if rank == 0 {
			break
		}
	}

	if bestName == "" {
		return "", fmt.Errorf("no binary named %s found in archive", strings.Join(preferredNames, ", "))
	}
	return bestName, nil
}

func installBinaryWithBackup(sourceBinary, installPath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(installPath), 0o755); err != nil {
		return "", fmt.Errorf("creating install directory: %w", err)
	}

	stagePath := installPath + ".new"
	if err := copyFile(sourceBinary, stagePath, 0o755); err != nil {
		return "", err
	}

	backupPath := ""
	if _, err := os.Stat(installPath); err == nil {
		backupPath = fmt.Sprintf("%s.bak.%s", installPath, timestampSuffix())
		if err := os.Rename(installPath, backupPath); err != nil {
			_ = os.Remove(stagePath)
			return "", fmt.Errorf("creating backup %q: %w", backupPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(stagePath)
		return "", fmt.Errorf("checking existing install path %q: %w", installPath, err)
	}

	if err := os.Rename(stagePath, installPath); err != nil {
		if backupPath != "" {
			_ = os.Rename(backupPath, installPath)
		}
		_ = os.Remove(stagePath)
		return "", fmt.Errorf("installing new binary: %w", err)
	}

	return backupPath, nil
}

func replaceDirectoryWithBackup(sourceDir, targetDir string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(targetDir), 0o755); err != nil {
		return "", fmt.Errorf("creating target parent directory: %w", err)
	}

	stageDir := fmt.Sprintf("%s.new.%s", targetDir, timestampSuffix())
	if err := copyDir(sourceDir, stageDir); err != nil {
		return "", err
	}

	backupPath := ""
	if _, err := os.Stat(targetDir); err == nil {
		backupPath = fmt.Sprintf("%s.bak.%s", targetDir, timestampSuffix())
		if err := os.Rename(targetDir, backupPath); err != nil {
			_ = os.RemoveAll(stageDir)
			return "", fmt.Errorf("creating backup %q: %w", backupPath, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = os.RemoveAll(stageDir)
		return "", fmt.Errorf("checking existing target directory %q: %w", targetDir, err)
	}

	if err := os.Rename(stageDir, targetDir); err != nil {
		if backupPath != "" {
			_ = os.Rename(backupPath, targetDir)
		}
		_ = os.RemoveAll(stageDir)
		return "", fmt.Errorf("installing new directory: %w", err)
	}

	return backupPath, nil
}

func copyDir(sourceDir, destinationDir string) error {
	return filepath.Walk(sourceDir, func(sourcePath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		relPath, err := filepath.Rel(sourceDir, sourcePath)
		if err != nil {
			return fmt.Errorf("computing relative path for %q: %w", sourcePath, err)
		}
		targetPath := filepath.Join(destinationDir, relPath)

		if info.IsDir() {
			return os.MkdirAll(targetPath, 0o755)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsupported symlink in source tree: %s", sourcePath)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported non-regular file in source tree: %s", sourcePath)
		}

		return copyFile(sourcePath, targetPath, info.Mode().Perm())
	})
}

func copyFile(sourcePath, destinationPath string, mode os.FileMode) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("opening source file %q: %w", sourcePath, err)
	}
	defer source.Close()

	if err := os.MkdirAll(filepath.Dir(destinationPath), 0o755); err != nil {
		return fmt.Errorf("creating directory for %q: %w", destinationPath, err)
	}

	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("opening destination file %q: %w", destinationPath, err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		return fmt.Errorf("copying %q to %q: %w", sourcePath, destinationPath, err)
	}
	if err := destination.Close(); err != nil {
		return fmt.Errorf("closing destination file %q: %w", destinationPath, err)
	}
	if err := os.Chmod(destinationPath, mode); err != nil {
		return fmt.Errorf("setting mode on %q: %w", destinationPath, err)
	}
	return nil
}

func writeReaderToFile(outputPath string, reader io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("creating directory for %q: %w", outputPath, err)
	}
	out, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("opening output file %q: %w", outputPath, err)
	}
	if _, err := io.Copy(out, reader); err != nil {
		_ = out.Close()
		return fmt.Errorf("writing output file %q: %w", outputPath, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("closing output file %q: %w", outputPath, err)
	}
	if err := os.Chmod(outputPath, mode); err != nil {
		return fmt.Errorf("setting mode on %q: %w", outputPath, err)
	}
	return nil
}

func writeSignatureSourceMetadata(rulesDir, repo string, release githubRelease, archiveURL string) (string, error) {
	sigmaRulesRoot := findAncestorDir(rulesDir, "sigma-rules")
	if sigmaRulesRoot == "" {
		return "", nil
	}

	metadataPath := filepath.Join(sigmaRulesRoot, "SOURCE.txt")
	content := fmt.Sprintf(
		"repo=https://github.com/%s\nrelease=%s\narchive=%s\nupdated_at=%s\nincluded_path=rules/linux\n",
		repo,
		release.TagName,
		archiveURL,
		time.Now().UTC().Format(time.RFC3339),
	)
	if err := os.WriteFile(metadataPath, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", metadataPath, err)
	}
	return metadataPath, nil
}

func findAncestorDir(candidatePath, dirName string) string {
	current := filepath.Clean(candidatePath)
	if info, err := os.Stat(current); err == nil && !info.IsDir() {
		current = filepath.Dir(current)
	}

	for {
		if filepath.Base(current) == dirName {
			return current
		}
		next := filepath.Dir(current)
		if next == current {
			return ""
		}
		current = next
	}
}

func safeJoin(root, relative string) (string, error) {
	target := filepath.Join(root, relative)
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", fmt.Errorf("resolving destination path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive entry escapes destination: %s", relative)
	}
	return target, nil
}

func relFromArchiveSubdir(archiveEntryPath, sourceSubdir string) (string, bool) {
	entry := path.Clean(strings.TrimPrefix(archiveEntryPath, "/"))
	subdir := path.Clean(strings.Trim(sourceSubdir, "/"))

	if entry == "." || subdir == "." || subdir == "" {
		if entry == "." {
			return "", false
		}
		return entry, true
	}

	entryParts := strings.Split(entry, "/")
	subParts := strings.Split(subdir, "/")
	if len(entryParts) < len(subParts) {
		return "", false
	}

	for i := 0; i+len(subParts) <= len(entryParts); i++ {
		if !equalStringSlices(entryParts[i:i+len(subParts)], subParts) {
			continue
		}
		after := entryParts[i+len(subParts):]
		if len(after) == 0 {
			return "", true
		}
		return path.Join(after...), true
	}

	return "", false
}

func detectArchiveFormat(archivePath string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("opening archive %q: %w", archivePath, err)
	}
	defer f.Close()

	var magic [4]byte
	n, err := io.ReadFull(f, magic[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", fmt.Errorf("reading archive header for %q: %w", archivePath, err)
	}

	if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		return "tar.gz", nil
	}
	if n >= 4 && magic[0] == 0x50 && magic[1] == 0x4b && magic[2] == 0x03 && magic[3] == 0x04 {
		return "zip", nil
	}

	lower := strings.ToLower(archivePath)
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		return "tar.gz", nil
	}
	if strings.HasSuffix(lower, ".zip") {
		return "zip", nil
	}

	return "", fmt.Errorf("unsupported archive format: %s", archivePath)
}

func preferredNameRank(name string, preferredNames []string) int {
	for i, preferred := range preferredNames {
		if strings.EqualFold(name, preferred) {
			return i
		}
	}
	return -1
}

func normalizeAliases(value string, aliasTable map[string][]string) []string {
	valueLower := strings.ToLower(strings.TrimSpace(value))
	aliases, ok := aliasTable[valueLower]
	if !ok {
		return []string{valueLower}
	}
	return aliases
}

func containsAny(value string, candidates []string) bool {
	valueLower := strings.ToLower(value)
	for _, candidate := range candidates {
		if candidate != "" && strings.Contains(valueLower, strings.ToLower(candidate)) {
			return true
		}
	}
	return false
}

func isArchiveName(name string) bool {
	return strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") || strings.HasSuffix(name, ".zip")
}

func validRepo(repo string) bool {
	parts := strings.Split(repo, "/")
	return len(parts) == 2 && strings.TrimSpace(parts[0]) != "" && strings.TrimSpace(parts[1]) != ""
}

func archiveSuffix(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".tar.gz"):
		return ".tar.gz"
	case strings.HasSuffix(lower, ".tgz"):
		return ".tgz"
	case strings.HasSuffix(lower, ".zip"):
		return ".zip"
	default:
		return ".archive"
	}
}

func resolveToken(flagValue string) string {
	if strings.TrimSpace(flagValue) != "" {
		return strings.TrimSpace(flagValue)
	}
	return strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
}

func timestampSuffix() string {
	return time.Now().UTC().Format("20060102T150405Z")
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
