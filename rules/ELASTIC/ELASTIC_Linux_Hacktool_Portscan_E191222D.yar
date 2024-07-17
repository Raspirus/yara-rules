rule ELASTIC_Linux_Hacktool_Portscan_E191222D : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Portscan (Linux.Hacktool.Portscan)"
		author = "Elastic Security"
		id = "e191222d-633a-4408-9a54-a70bb9e89cc0"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Portscan.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e2f4313538c3ef23adbfc50f37451c318bfd1ffd0e5aaa346cce4cc37417f812"
		logic_hash = "6ffb2add4a76214ffd555cf1fe356371acd3638216094097b355670ecfe02ecd"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5580dd8b9180b8ff36c7d08a134b1b3782b41054d8b29b23fc5a79e7b0059fd1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 46 4F 55 4E 44 00 56 41 4C 55 45 00 44 45 4C 45 54 45 44 00 54 }

	condition:
		all of them
}