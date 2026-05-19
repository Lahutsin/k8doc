package diagnostics

// removedAPIMatrix is a data-only table of Kubernetes API removals that upgrade-readiness
// uses to turn generic deprecated API findings into concrete target-version blockers.
// Releases not present here currently have no tracked removals in this matrix.
var removedAPIMatrix = []removedAPI{
	{Group: "extensions", Version: "v1beta1", Resource: "ingresses", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "networking.k8s.io/v1", Note: "Ingress moved to networking.k8s.io/v1."},
	{Group: "networking.k8s.io", Version: "v1beta1", Resource: "ingresses", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "networking.k8s.io/v1", Note: "Ingress beta API was removed."},
	{Group: "networking.k8s.io", Version: "v1beta1", Resource: "ingressclasses", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "networking.k8s.io/v1", Note: "IngressClass beta API was removed."},
	{Group: "admissionregistration.k8s.io", Version: "v1beta1", Resource: "validatingwebhookconfigurations", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "admissionregistration.k8s.io/v1", Note: "ValidatingWebhookConfiguration must use the v1 API."},
	{Group: "admissionregistration.k8s.io", Version: "v1beta1", Resource: "mutatingwebhookconfigurations", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "admissionregistration.k8s.io/v1", Note: "MutatingWebhookConfiguration must use the v1 API."},
	{Group: "apiextensions.k8s.io", Version: "v1beta1", Resource: "customresourcedefinitions", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "apiextensions.k8s.io/v1", Note: "CRDs must use the structural v1 API."},
	{Group: "apiregistration.k8s.io", Version: "v1beta1", Resource: "apiservices", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "apiregistration.k8s.io/v1", Note: "APIService beta API was removed."},
	{Group: "authentication.k8s.io", Version: "v1beta1", Resource: "tokenreviews", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "authentication.k8s.io/v1", Note: "TokenReview beta API was removed."},
	{Group: "authorization.k8s.io", Version: "v1beta1", Resource: "localsubjectaccessreviews", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "authorization.k8s.io/v1", Note: "SubjectAccessReview beta APIs were removed."},
	{Group: "authorization.k8s.io", Version: "v1beta1", Resource: "selfsubjectaccessreviews", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "authorization.k8s.io/v1", Note: "SubjectAccessReview beta APIs were removed."},
	{Group: "authorization.k8s.io", Version: "v1beta1", Resource: "subjectaccessreviews", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "authorization.k8s.io/v1", Note: "SubjectAccessReview beta APIs were removed."},
	{Group: "authorization.k8s.io", Version: "v1beta1", Resource: "selfsubjectrulesreviews", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "authorization.k8s.io/v1", Note: "SelfSubjectRulesReview beta API was removed."},
	{Group: "certificates.k8s.io", Version: "v1beta1", Resource: "certificatesigningrequests", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "certificates.k8s.io/v1", Note: "CSR beta API was removed."},
	{Group: "coordination.k8s.io", Version: "v1beta1", Resource: "leases", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "coordination.k8s.io/v1", Note: "Lease beta API was removed."},
	{Group: "rbac.authorization.k8s.io", Version: "v1beta1", Resource: "clusterroles", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "rbac.authorization.k8s.io/v1", Note: "RBAC beta APIs were removed."},
	{Group: "rbac.authorization.k8s.io", Version: "v1beta1", Resource: "clusterrolebindings", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "rbac.authorization.k8s.io/v1", Note: "RBAC beta APIs were removed."},
	{Group: "rbac.authorization.k8s.io", Version: "v1beta1", Resource: "roles", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "rbac.authorization.k8s.io/v1", Note: "RBAC beta APIs were removed."},
	{Group: "rbac.authorization.k8s.io", Version: "v1beta1", Resource: "rolebindings", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "rbac.authorization.k8s.io/v1", Note: "RBAC beta APIs were removed."},
	{Group: "scheduling.k8s.io", Version: "v1beta1", Resource: "priorityclasses", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "scheduling.k8s.io/v1", Note: "PriorityClass beta API was removed."},
	{Group: "storage.k8s.io", Version: "v1beta1", Resource: "csidrivers", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "storage.k8s.io/v1", Note: "Storage beta APIs were removed."},
	{Group: "storage.k8s.io", Version: "v1beta1", Resource: "csinodes", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "storage.k8s.io/v1", Note: "Storage beta APIs were removed."},
	{Group: "storage.k8s.io", Version: "v1beta1", Resource: "storageclasses", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "storage.k8s.io/v1", Note: "Storage beta APIs were removed."},
	{Group: "storage.k8s.io", Version: "v1beta1", Resource: "volumeattachments", RemovedIn: kubernetesVersion{Major: 1, Minor: 22, Raw: "v1.22"}, Successor: "storage.k8s.io/v1", Note: "Storage beta APIs were removed."},

	{Group: "batch", Version: "v1beta1", Resource: "cronjobs", RemovedIn: kubernetesVersion{Major: 1, Minor: 25, Raw: "v1.25"}, Successor: "batch/v1", Note: "CronJob GA API is batch/v1."},
	{Group: "discovery.k8s.io", Version: "v1beta1", Resource: "endpointslices", RemovedIn: kubernetesVersion{Major: 1, Minor: 25, Raw: "v1.25"}, Successor: "discovery.k8s.io/v1", Note: "EndpointSlice beta API was removed."},
	{Group: "events.k8s.io", Version: "v1beta1", Resource: "events", RemovedIn: kubernetesVersion{Major: 1, Minor: 25, Raw: "v1.25"}, Successor: "events.k8s.io/v1", Note: "Events beta API was removed."},
	{Group: "autoscaling", Version: "v2beta1", Resource: "horizontalpodautoscalers", RemovedIn: kubernetesVersion{Major: 1, Minor: 25, Raw: "v1.25"}, Successor: "autoscaling/v2", Note: "Use autoscaling/v2 for HPA."},
	{Group: "policy", Version: "v1beta1", Resource: "poddisruptionbudgets", RemovedIn: kubernetesVersion{Major: 1, Minor: 25, Raw: "v1.25"}, Successor: "policy/v1", Note: "PDBs must use policy/v1."},
	{Group: "policy", Version: "v1beta1", Resource: "podsecuritypolicies", RemovedIn: kubernetesVersion{Major: 1, Minor: 25, Raw: "v1.25"}, Successor: "Pod Security Admission or an external policy engine", Note: "PodSecurityPolicy was removed entirely."},
	{Group: "node.k8s.io", Version: "v1beta1", Resource: "runtimeclasses", RemovedIn: kubernetesVersion{Major: 1, Minor: 25, Raw: "v1.25"}, Successor: "node.k8s.io/v1", Note: "RuntimeClass beta API was removed."},

	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta1", Resource: "flowschemas", RemovedIn: kubernetesVersion{Major: 1, Minor: 26, Raw: "v1.26"}, Successor: "flowcontrol.apiserver.k8s.io/v1beta2", Note: "FlowSchema v1beta1 was removed."},
	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta1", Resource: "prioritylevelconfigurations", RemovedIn: kubernetesVersion{Major: 1, Minor: 26, Raw: "v1.26"}, Successor: "flowcontrol.apiserver.k8s.io/v1beta2", Note: "PriorityLevelConfiguration v1beta1 was removed."},
	{Group: "autoscaling", Version: "v2beta2", Resource: "horizontalpodautoscalers", RemovedIn: kubernetesVersion{Major: 1, Minor: 26, Raw: "v1.26"}, Successor: "autoscaling/v2", Note: "Use autoscaling/v2 for HPA."},

	{Group: "storage.k8s.io", Version: "v1beta1", Resource: "csistoragecapacities", RemovedIn: kubernetesVersion{Major: 1, Minor: 27, Raw: "v1.27"}, Successor: "storage.k8s.io/v1", Note: "CSIStorageCapacity beta API was removed."},

	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta2", Resource: "flowschemas", RemovedIn: kubernetesVersion{Major: 1, Minor: 29, Raw: "v1.29"}, Successor: "flowcontrol.apiserver.k8s.io/v1beta3 or v1", Note: "FlowSchema v1beta2 was removed."},
	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta2", Resource: "prioritylevelconfigurations", RemovedIn: kubernetesVersion{Major: 1, Minor: 29, Raw: "v1.29"}, Successor: "flowcontrol.apiserver.k8s.io/v1beta3 or v1", Note: "PriorityLevelConfiguration v1beta2 was removed."},

	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta3", Resource: "flowschemas", RemovedIn: kubernetesVersion{Major: 1, Minor: 32, Raw: "v1.32"}, Successor: "flowcontrol.apiserver.k8s.io/v1", Note: "FlowSchema v1beta3 was removed."},
	{Group: "flowcontrol.apiserver.k8s.io", Version: "v1beta3", Resource: "prioritylevelconfigurations", RemovedIn: kubernetesVersion{Major: 1, Minor: 32, Raw: "v1.32"}, Successor: "flowcontrol.apiserver.k8s.io/v1", Note: "PriorityLevelConfiguration v1beta3 was removed."},
}