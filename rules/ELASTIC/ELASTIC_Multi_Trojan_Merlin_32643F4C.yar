
rule ELASTIC_Multi_Trojan_Merlin_32643F4C : FILE MEMORY
{
	meta:
		description = "Detects Multi Trojan Merlin (Multi.Trojan.Merlin)"
		author = "Elastic Security"
		id = "32643f4c-ee47-4ed2-9807-7b85d3f4e095"
		date = "2024-03-01"
		modified = "2024-05-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Multi_Trojan_Merlin.yar#L1-L28"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "84b988c4656677bc021e23df2a81258212d9ceba13be204867ac1d9d706404e2"
		logic_hash = "7de2deec0e2c7fd3ce2b42762f88bfe87cb4ffb02b697953aa1716425d6f1612"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "bce277ef43c67be52b67c4495652e99d4707975c79cb30b54283db56545278ae"
		severity = 100
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$a1 = "json:\"killdate,omitempty\""
		$a2 = "json:\"maxretry,omitempty\""
		$a3 = "json:\"waittime,omitempty\""
		$a4 = "json:\"payload,omitempty\""
		$a5 = "json:\"skew,omitempty\""
		$a6 = "json:\"command\""
		$a7 = "json:\"pid,omitempty\""
		$b1 = "/merlin-agent/commands"
		$b2 = "/merlin/pkg/jobs"
		$b3 = "github.com/Ne0nd0g/merlin"

	condition:
		all of ($a*) or all of ($b*)
}