# Run with: opa test policy/ -v
package system.authz_test

import rego.v1
import data.system.authz

gateway_certificate := {
	"URIs": [{
		"Scheme": "spiffe",
		"Host": "secure-agent-gateway",
		"Path": "/gateway",
	}],
}

test_allow_health_check if {
	authz.allow with input as {
		"client_certificates": [gateway_certificate],
		"method": "GET",
		"path": ["health"],
	}
}

test_allow_gateway_decision_query if {
	authz.allow with input as {
		"client_certificates": [gateway_certificate],
		"method": "POST",
		"path": ["v1", "data", "gateway", "authz"],
	}
}

test_allow_gateway_decision_result_query if {
	authz.allow with input as {
		"client_certificates": [gateway_certificate],
		"method": "POST",
		"path": ["v1", "data", "gateway", "authz", "result"],
	}
}

test_deny_missing_workload_identity if {
	not authz.allow with input as {
		"method": "POST",
		"path": ["v1", "data", "gateway", "authz", "result"],
	}
}

test_deny_wrong_workload_identity if {
	not authz.allow with input as {
		"client_certificates": [{"URIs": [{
			"Scheme": "spiffe",
			"Host": "secure-agent-gateway",
			"Path": "/launcher",
		}]}],
		"method": "POST",
		"path": ["v1", "data", "gateway", "authz", "result"],
	}
}

test_deny_policy_upload if {
	not authz.allow with input as {"method": "PUT", "path": ["v1", "policies", "evil"]}
}

test_deny_policy_delete if {
	not authz.allow with input as {"method": "DELETE", "path": ["v1", "policies", "gateway"]}
}

test_deny_data_introspection if {
	not authz.allow with input as {"method": "GET", "path": ["v1", "data"]}
}

test_deny_data_mutation if {
	not authz.allow with input as {"method": "PATCH", "path": ["v1", "data", "gateway", "authz"]}
}

test_deny_wrong_method_on_allowed_path if {
	not authz.allow with input as {"method": "DELETE", "path": ["v1", "data", "gateway", "authz"]}
}

test_deny_unrelated_path if {
	not authz.allow with input as {"method": "GET", "path": ["v1", "query"]}
}
