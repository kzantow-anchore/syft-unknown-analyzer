package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	_ "github.com/glebarez/sqlite"
	"golang.org/x/exp/maps"

	"github.com/anchore/go-logger"
	"github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/go-sync"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

func main() {
	startAt := 0
	count := 1000
	parallelism := 4

	ctx := context.Background()
	executor := sync.NewExecutor(parallelism)

	resultDir := "results"
	if s, err := os.Stat(resultDir); err != nil || !s.IsDir() {
		panicOnError(os.MkdirAll(resultDir, 0700|os.ModeDir))
	}

	// set Syft statics
	syft.SetLogger(getOrPanic(logrus.New(logrus.Config{
		EnableConsole: true,
		Level:         logger.DebugLevel,
	})))

	startTime := time.Now()
	scanTimes := map[string]time.Duration{}

	// TODO check the total number of files
	total := atomic.Int64{}

	providers := []string{"registry"} // or "docker", etc.

	for idx, imageName := range sourcesIterator() {
		ref := imageName + ":latest"

		if idx < startAt {
			continue
		}
		if idx >= startAt+count {
			break
		}
		executor.Execute(func() {
			defer handlePanic()
			fmt.Printf("Scanning: %v %s\n", idx, ref)
			imageStartTime := time.Now()

			src := getOrPanic(syft.GetSource(ctx, ref, syft.DefaultGetSourceConfig().
				WithSources(providers...)))
			defer func() { _ = src.Close() }()

			fileCount := len(getOrPanic(getOrPanic(src.FileResolver(source.SquashedScope)).FilesByGlob("**/*")))
			total.Add(int64(fileCount))

			cfg := syft.DefaultCreateSBOMConfig().
				WithUnknownsConfig(cataloging.UnknownsConfig{
					RemoveWhenPackagesDefined:         false,
					IncludeExecutablesWithoutPackages: true,
					IncludeUnexpandedArchives:         true,
				}).
				WithFilesConfig(filecataloging.DefaultConfig().WithHashers())

			sbom := getOrPanic(syft.CreateSBOM(ctx, src, cfg))

			// ignore unknowns we don't care about, since we are not removing unknowns with packages
			filterUnknowns(sbom.Artifacts.Unknowns)

			resultFilePath := filepath.Join(resultDir, fmt.Sprintf("unknowns-%s.csv", strings.ReplaceAll(ref, ":", "_")))
			_ = os.Remove(resultFilePath)

			unknownMap := sbom.Artifacts.Unknowns
			if len(unknownMap) == 0 {
				return
			}

			f := getOrPanic(os.OpenFile(resultFilePath, os.O_CREATE|os.O_RDWR, 0600))
			defer func() { _ = f.Close() }()
			writeLn := func(line string, args ...any) {
				_ = getOrPanic(fmt.Fprintf(f, line, args...))
				_ = getOrPanic(fmt.Fprintln(f))
			}

			keys := maps.Keys(unknownMap)
			slices.SortFunc(keys, func(a, b file.Coordinates) int {
				return strings.Compare(a.RealPath, b.RealPath)
			})

			writeLn(`"IMAGE","FILE","TASK",ERROR"`)
			for _, coord := range keys {
				errs := unknownMap[coord]
				for _, err := range errs {
					parts := strings.SplitN(err, ": ", 2)
					tsk := ""
					if len(parts) > 1 {
						tsk = parts[0]
						err = parts[1]
					}
					writeLn(`"%s","%s","%s","%s"`, escapeQuotedCsv(ref), escapeQuotedCsv(coord.RealPath), escapeQuotedCsv(tsk), escapeQuotedCsv(err))
				}
			}

			scanTime := time.Now().Sub(imageStartTime)
			scanTimes[ref] = scanTime
			fmt.Printf("completed %v '%v' in %v\n", idx, ref, scanTime)

			if providers[0] == "docker" {
				img := getOrPanic(run("docker", "image", "list", "-aq", "-f", "reference="+ref))
				img = strings.TrimSpace(img)
				_ = getOrPanic(run("docker", "rmi", "-f", img))
			}
		})
	}

	executor.Wait()

	for ref, duration := range sorted(scanTimes) {
		fmt.Printf("%v\t%v\n", ref, duration)
	}
	fmt.Printf("all completed in %v; total files scanned: %v\n", time.Now().Sub(startTime), total.Load())
}

func sorted[K cmp.Ordered, V any](values map[K]V) func(func(K, V) bool) {
	keys := maps.Keys(values)
	slices.Sort(keys)
	return func(f func(K, V) bool) {
		for _, key := range keys {
			if !f(key, values[key]) {
				return
			}
		}
	}
}

func escapeQuotedCsv(value string) string {
	return strings.ReplaceAll(value, "\"", "\"\"")
}

func sourcesIterator() func(func(int, string) bool) {
	idx := 0

	return func(f func(int, string) bool) {
		next := "https://hub.docker.com/v2/repositories/library/?page_size=100"
		for {
			var sources []string
			sources, next = getImageList(next)
			for _, source := range sources {
				if !f(idx, source) {
					return
				}
				idx++
			}
			if next == "" {
				return
			}
		}
	}
}

func filterUnknowns(unknowns map[file.Coordinates][]string) {
	for k, errs := range unknowns {
		errs = filterErrs(errs)
		if len(errs) == 0 {
			delete(unknowns, k)
		} else {
			unknowns[k] = errs
		}
	}
}

func filterErrs(errs []string) []string {
	var out []string
	for _, err := range errs {
		if strings.Contains(err, "unable to determine ELF features") {
			continue
		}
		out = append(out, err)
	}
	return out
}

func handlePanic() {
	if err := recover(); err != nil {
		fmt.Printf("ERROR: %v\n", err)
	}
}

func getImageList(url string) ([]string, string) {
	rsp := getOrPanic(http.Get(url))
	defer func() { _ = rsp.Body.Close() }()

	var results map[string]any
	panicOnError(json.Unmarshal(getOrPanic(io.ReadAll(rsp.Body)), &results))

	next, _ := results["next"].(string)

	var images []string
	for _, result := range results["results"].([]any) {
		result := result.(map[string]any)
		images = append(images, result["name"].(string))
	}
	slices.Sort(images)
	return images, next
}

func run(command ...string) (string, error) {
	cmd := exec.Command(command[0], command[1:]...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func getOrPanic[T any](value T, err error) T {
	panicOnError(err)
	return value
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}
