package main

import (
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

	for idx, source := range sourcesIterator() {
		ref := source + ":latest"

		if idx < startAt {
			continue
		}
		if idx >= startAt+count {
			break
		}
		executor.Execute(func() {
			defer handlePanic()
			fmt.Printf("Scanning: %v %s\n", idx, ref)
			startTime := time.Now()

			src := getOrPanic(syft.GetSource(ctx, ref, syft.DefaultGetSourceConfig().
				WithSources("docker")))
			defer func() { _ = src.Close() }()

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

			f := getOrPanic(os.OpenFile(resultFilePath, os.O_CREATE|os.O_RDWR, 0600))
			defer func() { _ = f.Close() }()
			writeLn := func(line string, args ...any) {
				_ = getOrPanic(fmt.Fprintf(f, line, args...))
				_ = getOrPanic(fmt.Fprintln(f))
			}

			unknownMap := sbom.Artifacts.Unknowns
			keys := maps.Keys(unknownMap)
			slices.SortFunc(keys, func(a, b file.Coordinates) int {
				return strings.Compare(a.RealPath, b.RealPath)
			})

			writeLn(`"FILE","ERROR"`)
			for _, coord := range keys {
				errs := unknownMap[coord]
				for _, err := range errs {
					writeLn(`"%s","%s"`, escapeQuotedCsv(coord.RealPath), escapeQuotedCsv(err))
				}
			}

			fmt.Printf("completed %v '%v' in %v\n", idx, ref, time.Now().Sub(startTime))

			img := getOrPanic(run("docker", "images", "-aq", "-f", "reference="+ref))
			img = strings.TrimSpace(img)
			_ = getOrPanic(run("docker", "rmi", "-f", img))
		})
	}

	executor.Wait()
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
