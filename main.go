package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/anchore/go-sync"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

func main() {
	sources := getOfficialImages()

	startAt := 0
	count := 10
	parallelism := 2

	ctx := context.Background()
	executor := sync.NewExecutor(parallelism)

	resultDir := "results"
	if s, err := os.Stat(resultDir); err != nil || !s.IsDir() {
		panicOnError(os.MkdirAll(resultDir, 0700|os.ModeDir))
	}

	for i, source := range sources[startAt:] {
		if i > count {
			continue
		}
		executor.Execute(func() {
			defer handlePanic()
			fmt.Printf("Scanning: %s\n", source)
			src := getOrPanic(syft.GetSource(ctx, source, syft.DefaultGetSourceConfig().WithSources("docker")))
			defer func() { _ = src.Close() }()

			sbom := getOrPanic(syft.CreateSBOM(ctx, src, syft.DefaultCreateSBOMConfig().WithUnknownsConfig(cataloging.UnknownsConfig{
				RemoveWhenPackagesDefined:         false,
				IncludeExecutablesWithoutPackages: true,
				IncludeUnexpandedArchives:         true,
			})))

			// ignore unknowns we don't care about, since we are not removing unknowns with packages
			filterUnknowns(sbom.Artifacts.Unknowns)

			resultFilePath := filepath.Join(resultDir, fmt.Sprintf("unknowns-%s.csv", source))
			_ = os.Remove(resultFilePath)

			f := getOrPanic(os.OpenFile(resultFilePath, os.O_CREATE|os.O_RDWR, 0700))
			writeLn := func(line string, args ...any) {
				_ = getOrPanic(fmt.Fprintf(f, line, args...))
				_ = getOrPanic(fmt.Fprintln(f))
			}
			writeLn(`"FILE","ERROR"`)
			for coord, errs := range sbom.Artifacts.Unknowns {
				for _, err := range errs {
					writeLn(`"%s","%s"`, coord.RealPath, err)
				}
			}
		})
	}

	executor.Wait()
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

func getOfficialImages() []string {
	rsp := getOrPanic(http.Get("https://hub.docker.com/v2/repositories/library/?page_size=1000"))
	defer func() { _ = rsp.Body.Close() }()

	var results map[string]any
	panicOnError(json.Unmarshal(getOrPanic(io.ReadAll(rsp.Body)), &results))

	var images []string
	for _, result := range results["results"].([]any) {
		result := result.(map[string]any)
		images = append(images, result["name"].(string))
	}
	slices.Sort(images)
	return images
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
