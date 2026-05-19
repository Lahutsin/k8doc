package diagnostics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type manifestAPIDocument struct {
	Path       string
	APIVersion string
	Kind       string
}

type manifestUpgradeMatch struct {
	Document manifestAPIDocument
	Removed  removedAPI
}

type manifestScanWarning struct {
	Path   string
	Field  string
	Reason string
}

var manifestAPIVersionLinePattern = regexp.MustCompile(`(?m)^\s*apiVersion:\s*(.+?)\s*$`)
var manifestKindLinePattern = regexp.MustCompile(`(?m)^\s*kind:\s*(.+?)\s*$`)
var manifestDocumentSeparatorPattern = regexp.MustCompile(`(?m)^---(?:\s*#.*)?$`)
var quotedStringPattern = regexp.MustCompile(`"([^"]+)"|'([^']+)'`)
var literalAPIVersionPattern = regexp.MustCompile(`^[A-Za-z0-9./-]+$`)
var literalKindPattern = regexp.MustCompile(`^[A-Za-z0-9]+$`)
var helmDefinePattern = regexp.MustCompile(`(?s)\{\{-?\s*define\s+"([^"]+)"\s*-?\}\}(.*?)\{\{-?\s*end\s*-?\}\}`)
var helmIncludePattern = regexp.MustCompile(`(?:include|template)\s+"([^"]+)"|(?:include|template)\s+'([^']+)'`)

func EvaluateManifestUpgradeReadiness(targetVersion string, manifestPaths []string) ([]Advisory, error) {
	if strings.TrimSpace(targetVersion) == "" {
		return nil, nil
	}
	target, err := parseKubernetesVersion(targetVersion)
	if err != nil {
		return nil, err
	}
	paths, err := resolveManifestScanPaths(manifestPaths)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, nil
	}
	documents, scannedFiles, warnings, err := loadManifestAPIDocuments(paths)
	if err != nil {
		return nil, err
	}
	if scannedFiles == 0 {
		return nil, nil
	}
	advisories := make([]Advisory, 0, 2)
	matches := manifestRemovalBlockers(documents, target)
	if len(matches) == 0 {
		advisories = append(advisories, Advisory{
			Title:          "Manifest API Compatibility",
			Severity:       SeverityInfo,
			Summary:        fmt.Sprintf("scanned %d manifest files and found no APIs removed by %s", scannedFiles, target.Raw),
			Recommendation: fmt.Sprintf("Keep repository manifests on supported APIs and rerun this check before upgrading to %s.", target.Raw),
		})
	} else {
		examples := make([]string, 0, len(matches))
		uniqueRemoved := make([]removedAPI, 0, len(matches))
		seenRemoved := map[string]struct{}{}
		for _, match := range matches {
			examples = append(examples, fmt.Sprintf("%s uses %s %s", displayManifestPath(match.Document.Path), match.Document.APIVersion, match.Document.Kind))
			key := match.Removed.Group + "/" + match.Removed.Version + "/" + match.Removed.Resource
			if _, ok := seenRemoved[key]; ok {
				continue
			}
			seenRemoved[key] = struct{}{}
			uniqueRemoved = append(uniqueRemoved, match.Removed)
		}
		sort.Strings(examples)
		if len(examples) > 3 {
			examples = examples[:3]
		}
		advisories = append(advisories, Advisory{
			Title:          "Manifest API Compatibility",
			Severity:       SeverityCritical,
			Summary:        fmt.Sprintf("%d manifest definitions use APIs removed by %s, including %s", len(matches), target.Raw, strings.Join(examples, ", ")),
			Recommendation: buildRemovedAPIRecommendation(uniqueRemoved, target),
		})
	}
	if len(warnings) > 0 {
		advisories = append(advisories, buildManifestUncertaintyAdvisory(warnings, target))
	}
	return advisories, nil
}

func resolveManifestScanPaths(requested []string) ([]string, error) {
	if len(requested) > 0 {
		resolved := make([]string, 0, len(requested))
		for _, path := range requested {
			cleaned := filepath.Clean(path)
			if _, err := os.Stat(cleaned); err != nil {
				return nil, fmt.Errorf("manifest path %q: %w", path, err)
			}
			resolved = append(resolved, cleaned)
		}
		return resolved, nil
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	candidates := []string{"deploy", "manifests", "k8s", "charts", "helm"}
	resolved := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		path := filepath.Join(workingDir, candidate)
		if _, err := os.Stat(path); err == nil {
			resolved = append(resolved, path)
		}
	}
	return resolved, nil
}

func loadManifestAPIDocuments(paths []string) ([]manifestAPIDocument, int, []manifestScanWarning, error) {
	documents := make([]manifestAPIDocument, 0)
	warnings := make([]manifestScanWarning, 0)
	manifestFiles := map[string]struct{}{}
	allFiles := make([]string, 0)
	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			return nil, 0, nil, err
		}
		files := []string{root}
		if info.IsDir() {
			files, err = collectManifestFiles(root)
			if err != nil {
				return nil, 0, nil, err
			}
		}
		allFiles = append(allFiles, files...)
	}
	helperTemplates, err := loadHelmTemplateDefinitions(allFiles)
	if err != nil {
		return nil, 0, nil, err
	}
	for _, file := range allFiles {
		if !isManifestDocumentFile(file) {
			continue
		}
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, 0, nil, err
		}
		manifestFiles[file] = struct{}{}
		extracted, fileWarnings := extractManifestAPIDocuments(file, content, helperTemplates)
		documents = append(documents, extracted...)
		warnings = append(warnings, fileWarnings...)
	}
	return documents, len(manifestFiles), warnings, nil
}

func collectManifestFiles(root string) ([]string, error) {
	files := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".idea", ".vscode", "vendor", "node_modules", "bin", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" && ext != ".tpl" && ext != ".gotmpl" {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func loadHelmTemplateDefinitions(files []string) (map[string]string, error) {
	helperTemplates := make(map[string]string)
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		for _, match := range helmDefinePattern.FindAllSubmatch(content, -1) {
			if len(match) != 3 {
				continue
			}
			helperTemplates[string(match[1])] = string(match[2])
		}
	}
	return helperTemplates, nil
}

func isManifestDocumentFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml" || ext == ".json"
}

func extractManifestAPIDocuments(path string, content []byte, helperTemplates map[string]string) ([]manifestAPIDocument, []manifestScanWarning) {
	type partialDocument struct {
		APIVersion string `json:"apiVersion" yaml:"apiVersion"`
		Kind       string `json:"kind" yaml:"kind"`
	}

	documents := make([]manifestAPIDocument, 0)
	warnings := make([]manifestScanWarning, 0)
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return documents, warnings
	}

	var jsonDoc partialDocument
	if json.Unmarshal(trimmed, &jsonDoc) == nil && jsonDoc.APIVersion != "" && jsonDoc.Kind != "" {
		return append(documents, manifestAPIDocument{Path: path, APIVersion: jsonDoc.APIVersion, Kind: jsonDoc.Kind}), warnings
	}

	decoder := yaml.NewDecoder(bytes.NewReader(content))
	for {
		var doc partialDocument
		err := decoder.Decode(&doc)
		if err == io.EOF {
			if len(documents) > 0 {
				return documents, warnings
			}
			break
		}
		if err != nil {
			documents = documents[:0]
			break
		}
		if doc.APIVersion == "" || doc.Kind == "" {
			continue
		}
		documents = append(documents, manifestAPIDocument{Path: path, APIVersion: doc.APIVersion, Kind: doc.Kind})
	}

	parts := manifestDocumentSeparatorPattern.Split(string(content), -1)
	for _, part := range parts {
		apiVersions, apiWarning := extractManifestLineValuesDetailed(part, manifestAPIVersionLinePattern, literalAPIVersionPattern, helperTemplates)
		kinds, kindWarning := extractManifestLineValuesDetailed(part, manifestKindLinePattern, literalKindPattern, helperTemplates)
		if apiWarning != "" {
			warnings = append(warnings, manifestScanWarning{Path: path, Field: "apiVersion", Reason: apiWarning})
		}
		if kindWarning != "" {
			warnings = append(warnings, manifestScanWarning{Path: path, Field: "kind", Reason: kindWarning})
		}
		if len(apiVersions) == 0 || len(kinds) == 0 {
			continue
		}
		for _, apiVersion := range apiVersions {
			for _, kind := range kinds {
				documents = append(documents, manifestAPIDocument{Path: path, APIVersion: apiVersion, Kind: kind})
			}
		}
	}
	return documents, warnings
}

func extractManifestLineValues(document string, linePattern, literalPattern *regexp.Regexp, helperTemplates map[string]string) []string {
	values, _ := extractManifestLineValuesDetailed(document, linePattern, literalPattern, helperTemplates)
	return values
}

func extractManifestLineValuesDetailed(document string, linePattern, literalPattern *regexp.Regexp, helperTemplates map[string]string) ([]string, string) {
	matches := linePattern.FindStringSubmatch(document)
	if len(matches) != 2 {
		return nil, ""
	}
	raw := strings.TrimSpace(matches[1])
	raw = strings.TrimSuffix(raw, "#")
	raw = strings.TrimSpace(strings.SplitN(raw, " #", 2)[0])
	values, unresolvedHelpers := extractTemplateLiteralValues(raw, literalPattern, helperTemplates, map[string]struct{}{})
	if !strings.Contains(raw, "{{") {
		return values, ""
	}
	if len(unresolvedHelpers) > 0 {
		return values, fmt.Sprintf("references unresolved Helm helpers: %s", strings.Join(unresolvedHelpers, ", "))
	}
	if len(values) == 0 {
		return nil, "uses Helm templates without extractable literal values"
	}
	return values, ""
}

func extractTemplateLiteralValues(raw string, literalPattern *regexp.Regexp, helperTemplates map[string]string, seenHelpers map[string]struct{}) ([]string, []string) {
	values := make([]string, 0)
	seenValues := map[string]struct{}{}
	missingHelpers := make([]string, 0)
	seenMissingHelpers := map[string]struct{}{}
	trimmed := strings.TrimSpace(raw)
	if !strings.Contains(trimmed, "{{") && literalPattern.MatchString(strings.Trim(trimmed, `"'`)) {
		value := strings.Trim(raw, `"'`)
		seenValues[value] = struct{}{}
		values = append(values, value)
	}
	helperNames := extractHelmHelperNames(raw)
	helperNameSet := map[string]struct{}{}
	for _, helperName := range helperNames {
		helperNameSet[helperName] = struct{}{}
	}
	for _, candidate := range quotedStringPattern.FindAllStringSubmatch(raw, -1) {
		value := candidate[1]
		if value == "" {
			value = candidate[2]
		}
		value = strings.TrimSpace(value)
		if value == "" || !literalPattern.MatchString(value) {
			continue
		}
		if _, ok := helperNameSet[value]; ok {
			continue
		}
		if _, ok := seenValues[value]; ok {
			continue
		}
		seenValues[value] = struct{}{}
		values = append(values, value)
	}
	for _, helperName := range helperNames {
		if _, ok := seenHelpers[helperName]; ok {
			continue
		}
		helperBody, ok := helperTemplates[helperName]
		if !ok {
			if _, seen := seenMissingHelpers[helperName]; !seen {
				seenMissingHelpers[helperName] = struct{}{}
				missingHelpers = append(missingHelpers, helperName)
			}
			continue
		}
		nextSeen := make(map[string]struct{}, len(seenHelpers)+1)
		for name := range seenHelpers {
			nextSeen[name] = struct{}{}
		}
		nextSeen[helperName] = struct{}{}
		helperValues, unresolved := extractTemplateLiteralValues(helperBody, literalPattern, helperTemplates, nextSeen)
		for _, unresolvedName := range unresolved {
			if _, seen := seenMissingHelpers[unresolvedName]; seen {
				continue
			}
			seenMissingHelpers[unresolvedName] = struct{}{}
			missingHelpers = append(missingHelpers, unresolvedName)
		}
		for _, value := range helperValues {
			if _, ok := seenValues[value]; ok {
				continue
			}
			seenValues[value] = struct{}{}
			values = append(values, value)
		}
	}
	return values, missingHelpers
}

func buildManifestUncertaintyAdvisory(warnings []manifestScanWarning, target kubernetesVersion) Advisory {
	examples := make([]string, 0, len(warnings))
	seen := map[string]struct{}{}
	for _, warning := range warnings {
		key := warning.Path + ":" + warning.Field + ":" + warning.Reason
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		examples = append(examples, fmt.Sprintf("%s %s (%s)", displayManifestPath(warning.Path), warning.Field, warning.Reason))
	}
	sort.Strings(examples)
	if len(examples) > 3 {
		examples = examples[:3]
	}
	return Advisory{
		Title:          "Manifest Template Resolution Uncertainty",
		Severity:       SeverityWarning,
		Summary:        fmt.Sprintf("%d manifest template fields could not be resolved confidently for %s, including %s", len(seen), target.Raw, strings.Join(examples, ", ")),
		Recommendation: fmt.Sprintf("Review the unresolved manifest templates manually or render the chart for %s before relying on this upgrade check.", target.Raw),
	}
}

func extractHelmHelperNames(raw string) []string {
	seen := map[string]struct{}{}
	names := make([]string, 0)
	for _, match := range helmIncludePattern.FindAllStringSubmatch(raw, -1) {
		if len(match) != 3 {
			continue
		}
		name := match[1]
		if name == "" {
			name = match[2]
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

func manifestRemovalBlockers(documents []manifestAPIDocument, target kubernetesVersion) []manifestUpgradeMatch {
	matches := make([]manifestUpgradeMatch, 0)
	seen := map[string]struct{}{}
	for _, document := range documents {
		group, version := parseManifestAPIVersion(document.APIVersion)
		kind := strings.ToLower(strings.TrimSpace(document.Kind))
		for _, candidate := range removedAPIMatrix {
			if group != candidate.Group || version != candidate.Version {
				continue
			}
			if kind != strings.ToLower(removedAPIKind(candidate.Resource)) {
				continue
			}
			if !kubernetesVersionAtOrAfter(target, candidate.RemovedIn) {
				continue
			}
			key := document.Path + ":" + document.APIVersion + ":" + document.Kind
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			matches = append(matches, manifestUpgradeMatch{Document: document, Removed: candidate})
		}
	}
	return matches
}

func parseManifestAPIVersion(apiVersion string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(apiVersion), "/", 2)
	if len(parts) == 1 {
		return "", parts[0]
	}
	return parts[0], parts[1]
}

func removedAPIKind(resource string) string {
	switch resource {
	case "ingresses":
		return "Ingress"
	case "ingressclasses":
		return "IngressClass"
	case "validatingwebhookconfigurations":
		return "ValidatingWebhookConfiguration"
	case "mutatingwebhookconfigurations":
		return "MutatingWebhookConfiguration"
	case "customresourcedefinitions":
		return "CustomResourceDefinition"
	case "apiservices":
		return "APIService"
	case "tokenreviews":
		return "TokenReview"
	case "localsubjectaccessreviews":
		return "LocalSubjectAccessReview"
	case "selfsubjectaccessreviews":
		return "SelfSubjectAccessReview"
	case "subjectaccessreviews":
		return "SubjectAccessReview"
	case "selfsubjectrulesreviews":
		return "SelfSubjectRulesReview"
	case "certificatesigningrequests":
		return "CertificateSigningRequest"
	case "leases":
		return "Lease"
	case "clusterroles":
		return "ClusterRole"
	case "clusterrolebindings":
		return "ClusterRoleBinding"
	case "roles":
		return "Role"
	case "rolebindings":
		return "RoleBinding"
	case "priorityclasses":
		return "PriorityClass"
	case "csidrivers":
		return "CSIDriver"
	case "csinodes":
		return "CSINode"
	case "storageclasses":
		return "StorageClass"
	case "volumeattachments":
		return "VolumeAttachment"
	case "cronjobs":
		return "CronJob"
	case "endpointslices":
		return "EndpointSlice"
	case "events":
		return "Event"
	case "horizontalpodautoscalers":
		return "HorizontalPodAutoscaler"
	case "poddisruptionbudgets":
		return "PodDisruptionBudget"
	case "podsecuritypolicies":
		return "PodSecurityPolicy"
	case "runtimeclasses":
		return "RuntimeClass"
	case "flowschemas":
		return "FlowSchema"
	case "prioritylevelconfigurations":
		return "PriorityLevelConfiguration"
	case "csistoragecapacities":
		return "CSIStorageCapacity"
	default:
		return ""
	}
}

func displayManifestPath(path string) string {
	workingDir, err := os.Getwd()
	if err != nil {
		return path
	}
	relative, err := filepath.Rel(workingDir, path)
	if err != nil || strings.HasPrefix(relative, "..") {
		return path
	}
	return relative
}