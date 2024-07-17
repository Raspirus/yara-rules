rule ELASTIC_Linux_Trojan_Iroffer_0De95Cab : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Iroffer (Linux.Trojan.Iroffer)"
		author = "Elastic Security"
		id = "0de95cab-c671-44f0-a85e-5a5634e906f7"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Iroffer.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "717bea3902109d1b1d57e57c26b81442c0705af774139cd73105b2994ab89514"
		logic_hash = "adec3e1d3110bcc22262d5f1f2ad14a347616f4a809f29170a9fbb5d1669a4c3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "42c1ab8af313ec3c475535151ee67cac93ab6a25252b52b1e09c166065fb2760"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 41 52 52 45 43 4F 52 44 53 00 53 68 6F 77 20 49 6E 66 6F }

	condition:
		all of them
}