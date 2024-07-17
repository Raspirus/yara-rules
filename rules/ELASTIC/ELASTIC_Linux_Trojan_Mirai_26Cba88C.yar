
rule ELASTIC_Linux_Trojan_Mirai_26Cba88C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "26cba88c-7bd4-4fac-b395-04c4745fee43"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L239-L257"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4b4758bff3dcaa5640e340d27abba5c2e2b02c3c4a582374e183986375e49be8"
		logic_hash = "bb5a0f9e68655556ab9fccc27d11bf7828c299720bb67948455579d6a7eb2a9f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "358dd5d916fec3e1407c490ce0289886985be8fabee49581afbc01dcf941733e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F6 41 00 42 00 43 00 44 00 45 00 46 00 47 00 48 00 49 00 4A 00 }

	condition:
		all of them
}