rule ELASTIC_Linux_Trojan_Mirai_Ea584243 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "ea584243-6ead-4b96-9a5c-5b5dee12fd57"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L398-L416"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f363d9bd2132d969cd41e79f29c53ef403da64ca8afc4643084cc50076ddfb47"
		logic_hash = "34c6f800c849c295797cdd971fb4f3d16d680530f9a98c291388345569708208"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cbcabf4cba48152b3599570ef84503bfb8486db022a2b10df7544d4384023355"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C 81 FA }

	condition:
		all of them
}