# Helper package — not a rule.
# Regex-based HCL extraction for fugue-regula Terraform ports. Mirrors the
# pattern used in rules/cigna-confectionery/_lib/tf.rego.

package vulnetix.fugue.tf

import rego.v1

is_tf(path) if endswith(lower(path), ".tf")

resource_blocks(content, type) := out if {
	pattern := sprintf(`(?s)resource\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
	out := [r |
		some b in blocks
		name := _block_name(b)
		r := {"block": b, "name": name, "type": type}
	]
}

resources(type) := out if {
	out := [r |
		some path, content in input.file_contents
		is_tf(path)
		some rb in resource_blocks(content, type)
		r := {"path": path, "block": rb.block, "name": rb.name, "type": rb.type}
	]
}

data_blocks(content, type) := out if {
	pattern := sprintf(`(?s)data\s+"%s"\s+"[^"]+"\s*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*?\}`, [type])
	blocks := regex.find_n(pattern, content, -1)
	out := [r |
		some b in blocks
		name := _block_name(b)
		r := {"block": b, "name": name, "type": type}
	]
}

data_sources(type) := out if {
	out := [r |
		some path, content in input.file_contents
		is_tf(path)
		some rb in data_blocks(content, type)
		r := {"path": path, "block": rb.block, "name": rb.name, "type": rb.type}
	]
}

_block_name(block) := name if {
	captures := regex.find_n(`"([^"]+)"`, block, 2)
	count(captures) >= 2
	name := trim(captures[1], `"`)
}

string_attr(block, key) := val if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*"([^"]*)"`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	caps := regex.find_n(`"([^"]*)"`, matches[0], 1)
	count(caps) > 0
	val := trim(caps[0], `"`)
}

string_attrs(block, key) := vals if {
	pattern := sprintf(`(?m)%s\s*=\s*"([^"]*)"`, [key])
	matches := regex.find_n(pattern, block, -1)
	vals := [v |
		some m in matches
		caps := regex.find_n(`"([^"]*)"`, m, 1)
		count(caps) > 0
		v := trim(caps[0], `"`)
	]
}

bool_attr(block, key) := b if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*(true|false)\b`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	b := regex.match(`=\s*true\b`, matches[0])
}

number_attr(block, key) := n if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*([0-9]+)\b`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	digits := regex.find_n(`[0-9]+`, matches[0], -1)
	count(digits) > 0
	n := to_number(digits[count(digits) - 1])
}

string_list_attr(block, key) := vals if {
	pattern := sprintf(`(?s)%s\s*=\s*\[([^\]]*)\]`, [key])
	matches := regex.find_n(pattern, block, 1)
	count(matches) > 0
	body := matches[0]
	items := regex.find_n(`"([^"]*)"`, body, -1)
	vals := [v | some i in items; v := trim(i, `"`)]
}

has_key(block, key) if {
	pattern := sprintf(`(?m)^\s*%s\s*=`, [key])
	regex.match(pattern, block)
}

has_sub_block(block, name) if {
	regex.match(sprintf(`(?s)\b%s\s*\{`, [name]), block)
}

sub_blocks(block, name) := subs if {
	pattern := sprintf(`(?s)\b%s\s*\{((?:[^{}]|\{[^{}]*\})*?)\}`, [name])
	subs := regex.find_n(pattern, block, -1)
}

is_not_true(block, key) if not has_key(block, key)
is_not_true(block, key) if bool_attr(block, key) == false
is_not_true(block, key) if string_attr(block, key) == "false"

is_not_false(block, key) if not has_key(block, key)
is_not_false(block, key) if bool_attr(block, key) == true
is_not_false(block, key) if string_attr(block, key) == "true"

# Cross-resource reference: does `referrer_block` reference a resource of the
# given type+name in any attribute (e.g. `aws_vpc.main.id`)?
references(referrer_block, ref_type, ref_name) if {
	regex.match(sprintf(`\b%s\.%s\b`, [ref_type, ref_name]), referrer_block)
}

# Heredoc bodies for an attribute: `key = <<EOF\n...\nEOF`.
heredoc_attrs(block, key) := out if {
	pattern := sprintf(`(?s)%s\s*=\s*<<-?([A-Za-z0-9_]+)\s*\n(.*?)\n\s*\1\b`, [key])
	matches := regex.find_all_string_submatch_n(pattern, block, -1)
	out := [m[2] | some m in matches]
}

# Wildcard Allow *:* IAM statement in a policy text (heredoc JSON, quoted JSON,
# or jsonencode HCL map).
has_wildcard_allow_star(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Action"\s*:\s*"\*"[\s\S]*?"Resource"\s*:\s*"\*"`, block)
}

has_wildcard_allow_star(block) if {
	regex.match(`(?s)"Effect"\s*:\s*"Allow"[\s\S]*?"Resource"\s*:\s*"\*"[\s\S]*?"Action"\s*:\s*"\*"`, block)
}

has_wildcard_allow_star(block) if {
	regex.match(`(?s)Effect\s*=\s*"Allow"[\s\S]*?Action\s*=\s*"\*"[\s\S]*?Resource\s*=\s*"\*"`, block)
}

has_wildcard_allow_star(block) if {
	regex.match(`(?s)Effect\s*=\s*"Allow"[\s\S]*?Resource\s*=\s*"\*"[\s\S]*?Action\s*=\s*"\*"`, block)
}

has_service_star_action(block) if {
	regex.match(`"Action"\s*:\s*"[A-Za-z0-9\-]+:\*"`, block)
}

has_service_star_action(block) if {
	regex.match(`Action\s*=\s*"[A-Za-z0-9\-]+:\*"`, block)
}

has_not_action(block) if regex.match(`"NotAction"\s*:`, block)
has_not_action(block) if regex.match(`\bNotAction\s*=`, block)
