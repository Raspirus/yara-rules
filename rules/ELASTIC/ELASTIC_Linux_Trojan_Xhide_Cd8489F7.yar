
rule ELASTIC_Linux_Trojan_Xhide_Cd8489F7 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xhide (Linux.Trojan.Xhide)"
		author = "Elastic Security"
		id = "cd8489f7-795f-4fd5-b9a6-03ddd0f3bad4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xhide.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
		logic_hash = "34924260c811f1796ae37faec922bc21bb312ebb0672042d3ec27855f63ed61e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "30b2e0a8ad2fdaa040d748d8660477ae93a6ebc89a186029ff20392f6c968578"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 6F 74 2E 63 6F 6E 66 0A 0A 00 46 75 6C 6C 20 70 61 74 68 20 }

	condition:
		all of them
}