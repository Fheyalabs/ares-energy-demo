// Package releaseworkflow contains structural tests for
// .github/workflows/release-clients.yml. It parses the tracked YAML file
// directly (never a copy or a hand-summarized description of it) so these
// tests fail the moment the real workflow drifts from what they assert.
//
// This package intentionally does not attempt to run the workflow (that
// requires actual GitHub Actions runners with Xcode/NDK toolchains); it
// verifies the job graph, trigger, and step shape a real dispatch would
// exercise.
package releaseworkflow_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type step struct {
	Name            string         `yaml:"name"`
	Uses            string         `yaml:"uses"`
	Run             string         `yaml:"run"`
	If              string         `yaml:"if"`
	ContinueOnError bool           `yaml:"continue-on-error"`
	With            map[string]any `yaml:"with"`
}

type job struct {
	Name   string `yaml:"name"`
	Needs  needs  `yaml:"needs"`
	RunsOn string `yaml:"runs-on"`
	If     string `yaml:"if"`
	Steps  []step `yaml:"steps"`
}

// needs accepts GitHub Actions' `needs:` field in either its single-string
// or list-of-strings form and always exposes it as a slice.
type needs []string

func (n *needs) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var s string
		if err := value.Decode(&s); err != nil {
			return err
		}
		*n = []string{s}
		return nil
	case yaml.SequenceNode:
		var s []string
		if err := value.Decode(&s); err != nil {
			return err
		}
		*n = s
		return nil
	default:
		*n = nil
		return nil
	}
}

type workflow struct {
	Name        string         `yaml:"name"`
	On          map[string]any `yaml:"on"`
	Permissions map[string]any `yaml:"permissions"`
	Jobs        map[string]job `yaml:"jobs"`
}

func loadWorkflow(t *testing.T) (workflow, string) {
	return loadWorkflowFile(t, "release-clients.yml")
}

func loadWorkflowFile(t *testing.T, name string) (workflow, string) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// internal/releaseworkflow -> repo root
	repoRoot := filepath.Join(wd, "..", "..")
	path := filepath.Join(repoRoot, ".github", "workflows", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parsing %s as YAML: %v", path, err)
	}
	return wf, string(raw)
}

func TestOrdinaryGoWorkflowRunsFullSuiteOnUbuntu(t *testing.T) {
	wf, _ := loadWorkflowFile(t, "go.yml")
	testJob, ok := wf.Jobs["test"]
	if !ok {
		t.Fatal("ordinary Go workflow has no test job")
	}
	if testJob.RunsOn != "ubuntu-latest" {
		t.Errorf("ordinary Go test job runs-on = %q, want ubuntu-latest", testJob.RunsOn)
	}

	var testRun string
	for _, step := range testJob.Steps {
		if strings.Contains(step.Run, "go test") {
			testRun = step.Run
			break
		}
	}
	if !strings.Contains(testRun, "go test ./...") {
		t.Errorf("ordinary Ubuntu workflow does not run the complete Go suite: %q", testRun)
	}
	if strings.Contains(testRun, "GOOS=darwin") || strings.Contains(testRun, "-run") {
		t.Errorf("ordinary Ubuntu workflow narrows or cross-targets the complete Go suite: %q", testRun)
	}
}

func TestReleaseClientsWorkflowIsValidYAML(t *testing.T) {
	loadWorkflow(t) // fails the test on any parse error
}

func TestReleaseClientsWorkflowIsManualDispatchOnly(t *testing.T) {
	wf, _ := loadWorkflow(t)

	if _, ok := wf.On["workflow_dispatch"]; !ok {
		t.Fatal(`"on" does not declare workflow_dispatch`)
	}
	for _, forbidden := range []string{"push", "pull_request", "schedule", "workflow_run"} {
		if _, ok := wf.On[forbidden]; ok {
			t.Errorf("workflow declares automatic trigger %q; release-clients must be manual-dispatch only", forbidden)
		}
	}
	if len(wf.On) != 1 {
		t.Errorf("expected exactly one trigger (workflow_dispatch), got %d: %v", len(wf.On), wf.On)
	}
}

func TestReleaseClientsWorkflowGrantsNoWriteScopes(t *testing.T) {
	wf, _ := loadWorkflow(t)
	for scope, level := range wf.Permissions {
		levelStr, _ := level.(string)
		if levelStr == "write" {
			t.Errorf("permissions.%s = write; release-clients must never be able to tag, publish, or push (contents: read only)", scope)
		}
	}
	if got, _ := wf.Permissions["contents"].(string); got != "read" {
		t.Errorf(`permissions.contents = %q, want "read"`, got)
	}
}

func TestReleaseClientsWorkflowNeverTagsPublishesOrReleases(t *testing.T) {
	_, raw := loadWorkflow(t)
	lower := strings.ToLower(raw)
	for _, forbidden := range []string{
		"softprops/action-gh-release",
		"actions/create-release",
		"gh release create",
		"git tag",
		"git push --tags",
		"npm publish",
		"cocoapods",
		"pod trunk push",
		"maven-publish",
		"codesign",
	} {
		if strings.Contains(lower, strings.ToLower(forbidden)) {
			t.Errorf("workflow contains forbidden tag/publish/release/signing indicator %q", forbidden)
		}
	}
}

func TestReleaseClientsWorkflowNeverUsesTestOnlyOverrides(t *testing.T) {
	_, raw := loadWorkflow(t)
	for _, forbidden := range []string{
		"ARES_NATIVE_TEST_MODE",
		"ARES_NATIVE_TEST_PIN_FILE",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL",
		"ARES_NATIVE_TEST_NDK_PIN_FILE",
		"ARES_NATIVE_TEST_APPLE_DEPLOYMENT_TARGET_PIN_FILE",
	} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("workflow references test-only override %q; a real release dispatch must never activate a test escape hatch", forbidden)
		}
	}
}

func TestReleaseClientsWorkflowInvokesProductionAppleEntrypointDirectly(t *testing.T) {
	wf, _ := loadWorkflow(t)
	appleJob, ok := wf.Jobs["apple-xcframework"]
	if !ok {
		t.Fatal("release workflow has no apple-xcframework job")
	}
	var buildRun string
	for _, candidateStep := range appleJob.Steps {
		if strings.Contains(candidateStep.Run, "build-apple-xcframework.sh") {
			buildRun = candidateStep.Run
			break
		}
	}
	if !strings.Contains(buildRun, `./clients/native/build-apple-xcframework.sh "${out}"`) {
		t.Errorf("release workflow does not directly execute the production Apple entrypoint: %q", buildRun)
	}
	for _, forbidden := range []string{"source ", "run_apple_xcframework_build", "sw_vers_path", "otool_path"} {
		if strings.Contains(buildRun, forbidden) {
			t.Errorf("release workflow Apple invocation exposes test-harness boundary %q: %q", forbidden, buildRun)
		}
	}
}

func TestAutomaticMacOSReleaseSecurityWorkflow(t *testing.T) {
	wf, raw := loadWorkflowFile(t, "release-security-macos.yml")

	for _, event := range []string{"push", "pull_request"} {
		trigger, ok := wf.On[event]
		if !ok {
			t.Errorf("automatic macOS release-security workflow has no %s trigger", event)
			continue
		}
		triggerMap, ok := trigger.(map[string]any)
		if !ok {
			t.Errorf("%s trigger = %T, want a mapping with relevant paths", event, trigger)
			continue
		}
		pathValues, ok := triggerMap["paths"].([]any)
		if !ok {
			t.Errorf("%s trigger paths = %T, want a path list", event, triggerMap["paths"])
			continue
		}
		paths := make(map[string]bool, len(pathValues))
		for _, value := range pathValues {
			path, _ := value.(string)
			paths[path] = true
		}
		for _, required := range []string{
			"internal/releasebundle/**",
			"cmd/release-artifact-gate/**",
			"clients/native/**",
			"internal/releaseworkflow/**",
			"clients/swift/Package.release.swift",
			".github/workflows/go.yml",
			".github/workflows/release-security-macos.yml",
		} {
			if !paths[required] {
				t.Errorf("%s trigger omits relevant path %q (paths: %v)", event, required, paths)
			}
		}
	}
	if len(wf.On) != 2 {
		t.Errorf("automatic macOS workflow triggers = %v, want only push and pull_request", wf.On)
	}
	if got, _ := wf.Permissions["contents"].(string); got != "read" || len(wf.Permissions) != 1 {
		t.Errorf("automatic macOS workflow permissions = %v, want only contents: read", wf.Permissions)
	}

	requiredPackages := []string{
		"./internal/releasebundle",
		"./cmd/release-artifact-gate",
		"./clients/native",
		"./internal/releaseworkflow",
	}
	type candidate struct {
		job     job
		testRun string
	}
	var candidates []candidate
	for _, candidateJob := range wf.Jobs {
		for _, candidateStep := range candidateJob.Steps {
			matched := strings.Contains(candidateStep.Run, "go test")
			for _, pkg := range requiredPackages {
				matched = matched && strings.Contains(candidateStep.Run, pkg)
			}
			if matched {
				candidates = append(candidates, candidate{job: candidateJob, testRun: candidateStep.Run})
				break
			}
		}
	}
	if len(candidates) != 1 {
		t.Fatalf("found %d jobs running all focused release-security packages, want exactly 1", len(candidates))
	}
	releaseSecurityJob := candidates[0].job
	focusedTestRun := candidates[0].testRun
	if releaseSecurityJob.RunsOn != "macos-14" {
		t.Errorf("automatic release-security job runs-on = %q, want macos-14", releaseSecurityJob.RunsOn)
	}
	if releaseSecurityJob.If != "" {
		t.Errorf("automatic release-security job has skip condition %q", releaseSecurityJob.If)
	}
	for _, candidateStep := range releaseSecurityJob.Steps {
		if candidateStep.If != "" {
			t.Errorf("automatic release-security step %q has skip condition %q", candidateStep.Name, candidateStep.If)
		}
		if candidateStep.ContinueOnError {
			t.Errorf("automatic release-security step %q ignores failures", candidateStep.Name)
		}
	}
	for _, required := range []string{"-race", "-count=1"} {
		if !strings.Contains(focusedTestRun, required) {
			t.Errorf("focused go test command omits %s: %q", required, focusedTestRun)
		}
	}
	for _, forbidden := range []string{"-run", "-short", "-tags openfhe", "|| true", "set +e"} {
		if strings.Contains(focusedTestRun, forbidden) {
			t.Errorf("focused go test command contains forbidden narrowing/failure/build option %q: %q", forbidden, focusedTestRun)
		}
	}
	for _, forbidden := range []string{"build-apple-xcframework.sh", "openfhe-development", "cmake --build", "make -j"} {
		if strings.Contains(strings.ToLower(raw), strings.ToLower(forbidden)) {
			t.Errorf("automatic release-security workflow invokes an OpenFHE build indicator %q", forbidden)
		}
	}
}

func TestReleaseClientsWorkflowHasExpectedJobGraph(t *testing.T) {
	wf, _ := loadWorkflow(t)

	for _, name := range []string{"apple-xcframework", "android-aar"} {
		if _, ok := wf.Jobs[name]; !ok {
			t.Fatalf("workflow is missing expected job %q", name)
		}
	}

	gateName := findGateJob(t, wf)

	gate := wf.Jobs[gateName]
	if gate.RunsOn != "macos-14" {
		t.Errorf("gate job %q runs-on = %q, want pinned macos-14 so otool can inspect real Mach-O metadata", gateName, gate.RunsOn)
	}
	needSet := map[string]bool{}
	for _, n := range gate.Needs {
		needSet[n] = true
	}
	for _, want := range []string{"apple-xcframework", "android-aar"} {
		if !needSet[want] {
			t.Errorf("gate job %q does not depend on %q (needs: %v)", gateName, want, gate.Needs)
		}
	}
}

// findGateJob locates the job whose steps invoke the release-artifact-gate
// CLI, rather than hardcoding its name, so the test only fails if the
// behavior (running the gate) is missing, not if the job is renamed.
func findGateJob(t *testing.T, wf workflow) string {
	t.Helper()
	var candidates []string
	for name, j := range wf.Jobs {
		for _, s := range j.Steps {
			if strings.Contains(s.Run, "release-artifact-gate") {
				candidates = append(candidates, name)
				break
			}
		}
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		t.Fatal("no job in the workflow runs release-artifact-gate")
	}
	if len(candidates) > 1 {
		t.Fatalf("more than one job runs release-artifact-gate: %v", candidates)
	}
	return candidates[0]
}

func TestGateJobDownloadsBothPlatformArtifactsAndRunsAssembleThenVerify(t *testing.T) {
	wf, _ := loadWorkflow(t)
	gateName := findGateJob(t, wf)
	gate := wf.Jobs[gateName]

	var downloadedNames []string
	var downloadPaths []string
	assembleIdx, verifyIdx := -1, -1
	checkoutIdx := -1
	for i, s := range gate.Steps {
		if s.Uses != "" && strings.HasPrefix(s.Uses, "actions/checkout@") {
			checkoutIdx = i
		}
		if s.Uses != "" && strings.HasPrefix(s.Uses, "actions/download-artifact@") {
			if name, ok := s.With["name"].(string); ok {
				downloadedNames = append(downloadedNames, name)
			}
			if path, ok := s.With["path"].(string); ok {
				downloadPaths = append(downloadPaths, path)
			}
		}
		if strings.Contains(s.Run, "release-artifact-gate") && strings.Contains(s.Run, " assemble") {
			assembleIdx = i
		}
		if strings.Contains(s.Run, "release-artifact-gate") && strings.Contains(s.Run, " verify") {
			verifyIdx = i
		}
	}

	sort.Strings(downloadedNames)
	wantNames := []string{"openfhe-android-aar", "openfhe-apple-xcframework"}
	if len(downloadedNames) != len(wantNames) {
		t.Fatalf("gate job downloads artifacts %v, want exactly %v", downloadedNames, wantNames)
	}
	for i := range wantNames {
		if downloadedNames[i] != wantNames[i] {
			t.Errorf("gate job downloads artifacts %v, want %v", downloadedNames, wantNames)
		}
	}
	const wantFlatPath = "${{ runner.temp }}/release-bundle"
	if len(downloadPaths) != len(wantNames) {
		t.Fatalf("gate job download paths %v, want one explicit flat path for each platform artifact", downloadPaths)
	}
	for _, path := range downloadPaths {
		if path != wantFlatPath {
			t.Errorf("gate job artifact download path = %q, want shared explicit flat path %q", path, wantFlatPath)
		}
	}

	if checkoutIdx == -1 {
		t.Fatal("gate job does not check out the repository (no actions/checkout step)")
	}
	if assembleIdx == -1 {
		t.Fatal("gate job never runs `release-artifact-gate assemble`")
	}
	if verifyIdx == -1 {
		t.Fatal("gate job never runs `release-artifact-gate verify`")
	}
	if !(checkoutIdx < assembleIdx && assembleIdx < verifyIdx) {
		t.Errorf("expected step order checkout(%d) < downloads < assemble(%d) < verify(%d)", checkoutIdx, assembleIdx, verifyIdx)
	}
	for i, s := range gate.Steps {
		if s.Uses != "" && strings.HasPrefix(s.Uses, "actions/download-artifact@") && i >= assembleIdx {
			t.Errorf("artifact download step %q at index %d must occur before assemble at index %d", s.Name, i, assembleIdx)
		}
	}
}

func TestAllUploadArtifactStepsHaveBoundedRetentionAndFailOnMissingFiles(t *testing.T) {
	wf, _ := loadWorkflow(t)
	const maxRetentionDays = 30

	found := 0
	for jobName, j := range wf.Jobs {
		for _, s := range j.Steps {
			if s.Uses == "" || !strings.HasPrefix(s.Uses, "actions/upload-artifact@") {
				continue
			}
			found++
			retention, ok := s.With["retention-days"]
			if !ok {
				t.Errorf("job %q step %q: actions/upload-artifact has no retention-days (would default to the repo/org maximum)", jobName, s.Name)
				continue
			}
			days, ok := retention.(int)
			if !ok || days <= 0 || days > maxRetentionDays {
				t.Errorf("job %q step %q: retention-days = %v, want an int in (0, %d]", jobName, s.Name, retention, maxRetentionDays)
			}
			if got, _ := s.With["if-no-files-found"].(string); got != "error" {
				t.Errorf("job %q step %q: if-no-files-found = %q, want \"error\" (a silently-empty upload must not look like success)", jobName, s.Name, got)
			}
		}
	}
	if found == 0 {
		t.Fatal("workflow has no actions/upload-artifact steps at all")
	}
}

func TestReleaseClientsWorkflowStaysProductNeutral(t *testing.T) {
	_, raw := loadWorkflow(t)
	if strings.Contains(strings.ToLower(raw), "fheya") {
		t.Error("workflow file mentions Fheya; ARES-core public-facing artifacts must stay product-neutral")
	}
}
