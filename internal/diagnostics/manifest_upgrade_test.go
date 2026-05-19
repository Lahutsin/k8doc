package diagnostics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvaluateManifestUpgradeReadinessWithHelmTemplate(t *testing.T) {
	dir := t.TempDir()
	templateDir := filepath.Join(dir, "charts", "demo", "templates")
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	content := []byte(`{{- if .Values.ingress.enabled }}
apiVersion: {{ semverCompare ">=1.22-0" .Capabilities.KubeVersion.GitVersion | ternary "networking.k8s.io/v1" "extensions/v1beta1" }}
kind: {{ ternary "Ingress" "Ingress" .Values.ingress.enabled }}
metadata:
  name: demo
{{- end }}
`)
	path := filepath.Join(templateDir, "ingress.yaml")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	advisories, err := EvaluateManifestUpgradeReadiness("v1.22", []string{filepath.Join(dir, "charts")})
	if err != nil {
		t.Fatalf("EvaluateManifestUpgradeReadiness returned error: %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("expected one advisory, got %+v", advisories)
	}
	if advisories[0].Title != "Manifest API Compatibility" || advisories[0].Severity != SeverityCritical {
		t.Fatalf("expected critical manifest advisory, got %+v", advisories[0])
	}
	if !strings.Contains(advisories[0].Summary, "ingress.yaml uses extensions/v1beta1 Ingress") {
		t.Fatalf("expected templated ingress summary, got %q", advisories[0].Summary)
	}
	if !strings.Contains(advisories[0].Recommendation, "networking.k8s.io/v1") {
		t.Fatalf("expected successor API recommendation, got %q", advisories[0].Recommendation)
	}
}

func TestEvaluateManifestUpgradeReadinessWithHelmHelpers(t *testing.T) {
	dir := t.TempDir()
	templateDir := filepath.Join(dir, "charts", "demo", "templates")
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	helpers := []byte(`{{- define "demo.ingressApiVersionLiteral" -}}
{{ ternary "networking.k8s.io/v1" "extensions/v1beta1" .Values.ingress.enabled }}
{{- end -}}
{{- define "demo.ingressApiVersion" -}}
{{ include "demo.ingressApiVersionLiteral" . }}
{{- end -}}
{{- define "demo.ingressKind" -}}Ingress{{- end -}}
`)
	if err := os.WriteFile(filepath.Join(templateDir, "_helpers.tpl"), helpers, 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	manifest := []byte(`apiVersion: {{ tpl (include "demo.ingressApiVersion" .) . }}
kind: {{ include "demo.ingressKind" . }}
metadata:
  name: demo
`)
	if err := os.WriteFile(filepath.Join(templateDir, "ingress.yaml"), manifest, 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	advisories, err := EvaluateManifestUpgradeReadiness("v1.22", []string{filepath.Join(dir, "charts")})
	if err != nil {
		t.Fatalf("EvaluateManifestUpgradeReadiness returned error: %v", err)
	}
	if len(advisories) != 1 {
		t.Fatalf("expected one advisory, got %+v", advisories)
	}
	if advisories[0].Severity != SeverityCritical || !strings.Contains(advisories[0].Summary, "ingress.yaml uses extensions/v1beta1 Ingress") {
		t.Fatalf("expected helper-based manifest blocker, got %+v", advisories[0])
	}
}

func TestEvaluateManifestUpgradeReadinessWithUnresolvedHelpers(t *testing.T) {
	dir := t.TempDir()
	templateDir := filepath.Join(dir, "charts", "demo", "templates")
	if err := os.MkdirAll(templateDir, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	manifest := []byte(`apiVersion: {{ include "demo.missingApiVersion" . }}
kind: Ingress
metadata:
  name: demo
`)
	if err := os.WriteFile(filepath.Join(templateDir, "ingress.yaml"), manifest, 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	advisories, err := EvaluateManifestUpgradeReadiness("v1.22", []string{filepath.Join(dir, "charts")})
	if err != nil {
		t.Fatalf("EvaluateManifestUpgradeReadiness returned error: %v", err)
	}
	if len(advisories) != 2 {
		t.Fatalf("expected compatibility and uncertainty advisories, got %+v", advisories)
	}
	if advisories[0].Title != "Manifest API Compatibility" || advisories[0].Severity != SeverityInfo {
		t.Fatalf("expected informational compatibility advisory, got %+v", advisories[0])
	}
	if advisories[1].Title != "Manifest Template Resolution Uncertainty" || advisories[1].Severity != SeverityWarning {
		t.Fatalf("expected uncertainty advisory, got %+v", advisories[1])
	}
	if !strings.Contains(advisories[1].Summary, "demo.missingApiVersion") {
		t.Fatalf("expected unresolved helper in summary, got %q", advisories[1].Summary)
	}
}

func TestExtractManifestLineValues(t *testing.T) {
	document := `apiVersion: {{ ternary "networking.k8s.io/v1" "extensions/v1beta1" .Values.ingress.enabled }}
kind: {{ ternary "Ingress" "Ingress" .Values.ingress.enabled }}`
	apiVersions := extractManifestLineValues(document, manifestAPIVersionLinePattern, literalAPIVersionPattern, nil)
	if len(apiVersions) != 2 || apiVersions[0] != "networking.k8s.io/v1" || apiVersions[1] != "extensions/v1beta1" {
		t.Fatalf("expected apiVersion candidates, got %+v", apiVersions)
	}
	kinds := extractManifestLineValues(document, manifestKindLinePattern, literalKindPattern, nil)
	if len(kinds) != 1 || kinds[0] != "Ingress" {
		t.Fatalf("expected kind candidate, got %+v", kinds)
	}
}

func TestExtractManifestLineValuesFromHelperInclude(t *testing.T) {
	helperTemplates := map[string]string{
		"demo.ingressApiVersion": `{{ include "demo.ingressApiVersionLiteral" . }}`,
		"demo.ingressApiVersionLiteral": `{{ ternary "networking.k8s.io/v1" "extensions/v1beta1" .Values.ingress.enabled }}`,
	}
	apiVersions := extractManifestLineValues(`apiVersion: {{ include "demo.ingressApiVersion" . }}`, manifestAPIVersionLinePattern, literalAPIVersionPattern, helperTemplates)
	if len(apiVersions) != 2 || apiVersions[0] != "networking.k8s.io/v1" || apiVersions[1] != "extensions/v1beta1" {
		t.Fatalf("expected helper-derived apiVersion candidates, got %+v", apiVersions)
	}
}

func TestExtractManifestLineValuesDetailedReportsUnresolvedHelpers(t *testing.T) {
	values, reason := extractManifestLineValuesDetailed(`apiVersion: {{ include "demo.missingApiVersion" . }}`, manifestAPIVersionLinePattern, literalAPIVersionPattern, nil)
	if len(values) != 0 {
		t.Fatalf("expected no values for unresolved helper, got %+v", values)
	}
	if !strings.Contains(reason, "demo.missingApiVersion") {
		t.Fatalf("expected unresolved helper reason, got %q", reason)
	}
}