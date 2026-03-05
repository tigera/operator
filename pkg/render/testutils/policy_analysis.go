// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package testutils

import (
	"fmt"
	"regexp"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

// PodInfo captures pod identity for selector matching
type PodInfo struct {
	Namespace string
	Name      string            // Deployment/DaemonSet/StatefulSet name
	Labels    map[string]string // Pod template labels
	Component string            // Which operator component created this
	Kind      string            // Deployment, DaemonSet, or StatefulSet
}

// PolicyInfo captures network policy rules
type PolicyInfo struct {
	Namespace string
	Name      string
	Selector  string // Pod selector (which pods this applies to)
	Ingress   []RuleInfo
	Egress    []RuleInfo
	Component string
}

// RuleInfo captures a single rule
type RuleInfo struct {
	NamespaceSelector string
	Selector          string
	Ports             []uint16
	Services          *v3.ServiceMatch
	// IsSource indicates if this is a source rule (ingress) vs destination rule (egress)
	IsSource bool
}

// PolicyAnalysisResult captures validation findings
type PolicyAnalysisResult struct {
	PolicyName    string
	PolicyNS      string
	CheckType     string
	Passed        bool
	Message       string
	ActualLabels  map[string]string // For debugging mismatches
	ExpectedMatch string            // The selector that was expected to match
}

// PolicyAnalyzer contains the state for analyzing policies
type PolicyAnalyzer struct {
	pods     []PodInfo
	policies []PolicyInfo
	results  []PolicyAnalysisResult
}

// NewPolicyAnalyzer creates a new policy analyzer
func NewPolicyAnalyzer() *PolicyAnalyzer {
	return &PolicyAnalyzer{
		pods:     []PodInfo{},
		policies: []PolicyInfo{},
		results:  []PolicyAnalysisResult{},
	}
}

// ExtractPodInfoFromResources extracts PodInfo from Deployments, DaemonSets, and StatefulSets
func ExtractPodInfoFromResources(resources []client.Object, component string) []PodInfo {
	var pods []PodInfo

	for _, resource := range resources {
		switch obj := resource.(type) {
		case *appsv1.Deployment:
			// Use pod template labels, falling back to selector match labels, then deployment labels
			labels := obj.Spec.Template.Labels
			if len(labels) == 0 && obj.Spec.Selector != nil {
				labels = obj.Spec.Selector.MatchLabels
			}
			if len(labels) == 0 {
				labels = obj.Labels
			}
			pods = append(pods, PodInfo{
				Namespace: obj.Namespace,
				Name:      obj.Name,
				Labels:    labels,
				Component: component,
				Kind:      "Deployment",
			})
		case *appsv1.DaemonSet:
			labels := obj.Spec.Template.Labels
			if len(labels) == 0 && obj.Spec.Selector != nil {
				labels = obj.Spec.Selector.MatchLabels
			}
			if len(labels) == 0 {
				labels = obj.Labels
			}
			pods = append(pods, PodInfo{
				Namespace: obj.Namespace,
				Name:      obj.Name,
				Labels:    labels,
				Component: component,
				Kind:      "DaemonSet",
			})
		case *appsv1.StatefulSet:
			labels := obj.Spec.Template.Labels
			if len(labels) == 0 && obj.Spec.Selector != nil {
				labels = obj.Spec.Selector.MatchLabels
			}
			if len(labels) == 0 {
				labels = obj.Labels
			}
			pods = append(pods, PodInfo{
				Namespace: obj.Namespace,
				Name:      obj.Name,
				Labels:    labels,
				Component: component,
				Kind:      "StatefulSet",
			})
		}
	}

	return pods
}

// ExtractPolicyInfoFromResources extracts PolicyInfo from NetworkPolicy objects
func ExtractPolicyInfoFromResources(resources []client.Object, component string) []PolicyInfo {
	var policies []PolicyInfo

	for _, resource := range resources {
		switch obj := resource.(type) {
		case *v3.NetworkPolicy:
			policy := PolicyInfo{
				Namespace: obj.Namespace,
				Name:      obj.Name,
				Selector:  obj.Spec.Selector,
				Component: component,
			}

			// Extract ingress rules
			for _, rule := range obj.Spec.Ingress {
				policy.Ingress = append(policy.Ingress, extractRuleInfo(rule.Source, true))
			}

			// Extract egress rules
			for _, rule := range obj.Spec.Egress {
				policy.Egress = append(policy.Egress, extractRuleInfo(rule.Destination, false))
			}

			policies = append(policies, policy)
		}
	}

	return policies
}

// extractRuleInfo extracts RuleInfo from an EntityRule
func extractRuleInfo(entity v3.EntityRule, isSource bool) RuleInfo {
	var ports []uint16
	for _, p := range entity.Ports {
		ports = append(ports, p.MinPort)
	}

	return RuleInfo{
		NamespaceSelector: entity.NamespaceSelector,
		Selector:          entity.Selector,
		Ports:             ports,
		Services:          entity.Services,
		IsSource:          isSource,
	}
}

// AddPods adds pod info to the analyzer
func (a *PolicyAnalyzer) AddPods(pods []PodInfo) {
	a.pods = append(a.pods, pods...)
}

// AddPolicies adds policy info to the analyzer
func (a *PolicyAnalyzer) AddPolicies(policies []PolicyInfo) {
	a.policies = append(a.policies, policies...)
}

// Analyze performs all validation checks
func (a *PolicyAnalyzer) Analyze() []PolicyAnalysisResult {
	a.results = []PolicyAnalysisResult{}

	for _, policy := range a.policies {
		// Skip default-deny policies - they use "all()" selector which matches everything
		if strings.HasSuffix(policy.Name, "default-deny") {
			continue
		}

		// Check 1: Policy selector matches at least one pod in the namespace
		a.checkPolicySelectorMatchesPods(policy)

		// Check 2: Egress destination selectors match pods in target namespaces
		a.checkEgressDestinations(policy)

		// Check 3: Ingress source selectors match pods in source namespaces
		a.checkIngressSources(policy)
	}

	return a.results
}

// checkPolicySelectorMatchesPods verifies that a policy's selector matches at least one pod
func (a *PolicyAnalyzer) checkPolicySelectorMatchesPods(policy PolicyInfo) {
	// Skip empty selectors or special selectors
	if policy.Selector == "" || policy.Selector == "all()" {
		return
	}

	// Find pods in the same namespace
	var podsInNamespace []PodInfo
	for _, pod := range a.pods {
		if pod.Namespace == policy.Namespace {
			podsInNamespace = append(podsInNamespace, pod)
		}
	}

	if len(podsInNamespace) == 0 {
		// No pods in namespace - this might be OK if it's a policy for external traffic
		return
	}

	// Check if any pod matches the selector
	matched := false
	var unmatchedPods []PodInfo
	for _, pod := range podsInNamespace {
		if MatchesSelector(pod.Labels, policy.Selector) {
			matched = true
			break
		}
		unmatchedPods = append(unmatchedPods, pod)
	}

	result := PolicyAnalysisResult{
		PolicyName:    policy.Name,
		PolicyNS:      policy.Namespace,
		CheckType:     "policy-selector-matches-pods",
		Passed:        matched,
		ExpectedMatch: policy.Selector,
	}

	if !matched && len(unmatchedPods) > 0 {
		result.Message = fmt.Sprintf("Policy selector '%s' doesn't match any pods in namespace %s. Available pods: %v",
			policy.Selector, policy.Namespace, getPodLabelsDescription(unmatchedPods))
		result.ActualLabels = unmatchedPods[0].Labels
	} else if matched {
		result.Message = fmt.Sprintf("Policy selector '%s' matches pods in %s", policy.Selector, policy.Namespace)
	}

	a.results = append(a.results, result)
}

// checkEgressDestinations verifies that egress rules target existing pods
func (a *PolicyAnalyzer) checkEgressDestinations(policy PolicyInfo) {
	for i, rule := range policy.Egress {
		// Skip rules without selectors (e.g., service matches, net blocks)
		if rule.Selector == "" {
			continue
		}

		// Determine target namespace
		targetNS := extractNamespaceFromSelector(rule.NamespaceSelector)
		if targetNS == "" {
			targetNS = policy.Namespace // Same namespace if not specified
		}

		// Find pods in target namespace
		var podsInNamespace []PodInfo
		for _, pod := range a.pods {
			if pod.Namespace == targetNS {
				podsInNamespace = append(podsInNamespace, pod)
			}
		}

		// Check if any pod matches
		matched := false
		for _, pod := range podsInNamespace {
			if MatchesSelector(pod.Labels, rule.Selector) {
				matched = true
				break
			}
		}

		result := PolicyAnalysisResult{
			PolicyName:    policy.Name,
			PolicyNS:      policy.Namespace,
			CheckType:     fmt.Sprintf("egress-rule-%d-destination-exists", i),
			Passed:        matched || len(podsInNamespace) == 0, // Pass if no pods to check against
			ExpectedMatch: rule.Selector,
		}

		if !matched && len(podsInNamespace) > 0 {
			result.Message = fmt.Sprintf("Egress rule selector '%s' (namespace: %s) doesn't match any pods. Available in %s: %v",
				rule.Selector, rule.NamespaceSelector, targetNS, getPodLabelsDescription(podsInNamespace))
			result.ActualLabels = podsInNamespace[0].Labels
		} else if matched {
			result.Message = fmt.Sprintf("Egress to '%s' in %s matches existing pods", rule.Selector, targetNS)
		}

		a.results = append(a.results, result)
	}
}

// checkIngressSources verifies that ingress rules have valid source selectors
func (a *PolicyAnalyzer) checkIngressSources(policy PolicyInfo) {
	for i, rule := range policy.Ingress {
		// Skip rules without selectors
		if rule.Selector == "" {
			continue
		}

		// Determine source namespace
		sourceNS := extractNamespaceFromSelector(rule.NamespaceSelector)
		if sourceNS == "" {
			sourceNS = policy.Namespace
		}

		// Find pods in source namespace
		var podsInNamespace []PodInfo
		for _, pod := range a.pods {
			if pod.Namespace == sourceNS {
				podsInNamespace = append(podsInNamespace, pod)
			}
		}

		// Check if any pod matches
		matched := false
		for _, pod := range podsInNamespace {
			if MatchesSelector(pod.Labels, rule.Selector) {
				matched = true
				break
			}
		}

		result := PolicyAnalysisResult{
			PolicyName:    policy.Name,
			PolicyNS:      policy.Namespace,
			CheckType:     fmt.Sprintf("ingress-rule-%d-source-exists", i),
			Passed:        matched || len(podsInNamespace) == 0,
			ExpectedMatch: rule.Selector,
		}

		if !matched && len(podsInNamespace) > 0 {
			result.Message = fmt.Sprintf("Ingress rule selector '%s' (namespace: %s) doesn't match any pods. Available in %s: %v",
				rule.Selector, rule.NamespaceSelector, sourceNS, getPodLabelsDescription(podsInNamespace))
			result.ActualLabels = podsInNamespace[0].Labels
		} else if matched {
			result.Message = fmt.Sprintf("Ingress from '%s' in %s matches existing pods", rule.Selector, sourceNS)
		}

		a.results = append(a.results, result)
	}
}

// GetFailures returns only the failed validation results
func (a *PolicyAnalyzer) GetFailures() []PolicyAnalysisResult {
	var failures []PolicyAnalysisResult
	for _, r := range a.results {
		if !r.Passed {
			failures = append(failures, r)
		}
	}
	return failures
}

// GetPassed returns only the passed validation results
func (a *PolicyAnalyzer) GetPassed() []PolicyAnalysisResult {
	var passed []PolicyAnalysisResult
	for _, r := range a.results {
		if r.Passed {
			passed = append(passed, r)
		}
	}
	return passed
}

// MatchesSelector checks if labels match a Calico selector expression
// Supports common patterns like:
//   - k8s-app == 'value'
//   - k8s-app == 'value1' || k8s-app == 'value2'
//   - has(label)
//   - !has(label)
//   - all()
func MatchesSelector(labels map[string]string, selector string) bool {
	selector = strings.TrimSpace(selector)

	// Handle special selectors
	if selector == "" || selector == "all()" {
		return true
	}

	// Handle OR expressions (||)
	if strings.Contains(selector, "||") {
		parts := strings.Split(selector, "||")
		for _, part := range parts {
			if MatchesSelector(labels, strings.TrimSpace(part)) {
				return true
			}
		}
		return false
	}

	// Handle AND expressions (&&)
	if strings.Contains(selector, "&&") {
		parts := strings.Split(selector, "&&")
		for _, part := range parts {
			if !MatchesSelector(labels, strings.TrimSpace(part)) {
				return false
			}
		}
		return true
	}

	// Handle has(label)
	hasPattern := regexp.MustCompile(`^has\(([^)]+)\)$`)
	if matches := hasPattern.FindStringSubmatch(selector); len(matches) == 2 {
		_, exists := labels[matches[1]]
		return exists
	}

	// Handle !has(label)
	notHasPattern := regexp.MustCompile(`^!has\(([^)]+)\)$`)
	if matches := notHasPattern.FindStringSubmatch(selector); len(matches) == 2 {
		_, exists := labels[matches[1]]
		return !exists
	}

	// Handle label == 'value'
	eqPattern := regexp.MustCompile(`^([a-zA-Z0-9_./-]+)\s*==\s*'([^']*)'$`)
	if matches := eqPattern.FindStringSubmatch(selector); len(matches) == 3 {
		labelKey := matches[1]
		expectedValue := matches[2]
		actualValue, exists := labels[labelKey]
		return exists && actualValue == expectedValue
	}

	// Handle label != 'value'
	neqPattern := regexp.MustCompile(`^([a-zA-Z0-9_./-]+)\s*!=\s*'([^']*)'$`)
	if matches := neqPattern.FindStringSubmatch(selector); len(matches) == 3 {
		labelKey := matches[1]
		expectedValue := matches[2]
		actualValue, exists := labels[labelKey]
		return !exists || actualValue != expectedValue
	}

	// Handle label in {'value1', 'value2'}
	inPattern := regexp.MustCompile(`^([a-zA-Z0-9_./-]+)\s+in\s+\{([^}]+)\}$`)
	if matches := inPattern.FindStringSubmatch(selector); len(matches) == 3 {
		labelKey := matches[1]
		valuesStr := matches[2]
		actualValue, exists := labels[labelKey]
		if !exists {
			return false
		}
		// Parse values
		valuePattern := regexp.MustCompile(`'([^']*)'`)
		valueMatches := valuePattern.FindAllStringSubmatch(valuesStr, -1)
		for _, vm := range valueMatches {
			if vm[1] == actualValue {
				return true
			}
		}
		return false
	}

	// Unrecognized selector pattern - assume it doesn't match for safety
	// This is conservative to catch potential issues
	return false
}

// extractNamespaceFromSelector extracts namespace name from a namespace selector
// Handles patterns like: projectcalico.org/name == 'namespace'
func extractNamespaceFromSelector(selector string) string {
	if selector == "" {
		return ""
	}

	// Handle global() selector
	if selector == "global()" {
		return ""
	}

	// Common patterns:
	// projectcalico.org/name == 'namespace'
	// name == 'namespace'
	patterns := []string{
		`projectcalico\.org/name\s*==\s*'([^']+)'`,
		`name\s*==\s*'([^']+)'`,
	}

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if matches := re.FindStringSubmatch(selector); len(matches) == 2 {
			return matches[1]
		}
	}

	return ""
}

// getPodLabelsDescription returns a description of available pods and their k8s-app labels
func getPodLabelsDescription(pods []PodInfo) string {
	var descriptions []string
	for _, pod := range pods {
		k8sApp := pod.Labels["k8s-app"]
		if k8sApp != "" {
			descriptions = append(descriptions, fmt.Sprintf("%s(k8s-app=%s)", pod.Name, k8sApp))
		} else {
			descriptions = append(descriptions, pod.Name)
		}
	}
	return strings.Join(descriptions, ", ")
}

// FormatResults formats analysis results for display
func FormatResults(results []PolicyAnalysisResult) string {
	var sb strings.Builder
	sb.WriteString("=== Static Policy Analysis Results ===\n\n")

	passed := 0
	failed := 0

	for _, r := range results {
		if r.Passed {
			passed++
			sb.WriteString(fmt.Sprintf("PASS: %s/%s - %s\n", r.PolicyNS, r.PolicyName, r.CheckType))
			if r.Message != "" {
				sb.WriteString(fmt.Sprintf("      %s\n", r.Message))
			}
		} else {
			failed++
			sb.WriteString(fmt.Sprintf("FAIL: %s/%s - %s\n", r.PolicyNS, r.PolicyName, r.CheckType))
			sb.WriteString(fmt.Sprintf("      %s\n", r.Message))
			sb.WriteString(fmt.Sprintf("      Expected selector: %s\n", r.ExpectedMatch))
		}
	}

	sb.WriteString(fmt.Sprintf("\nSummary: %d checks passed, %d failed\n", passed, failed))
	return sb.String()
}
