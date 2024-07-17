
rule ELASTIC_Linux_Trojan_Gafgyt_Fbed4652 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "fbed4652-2c68-45c6-8116-e3fe7d0a28b8"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L276-L294"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "2ea21358205612f5dc0d5f417c498b236c070509531621650b8c215c98c49467"
		logic_hash = "fc1f501123ab7421034e183186b077f65838b475f883d4ff04e8fc8a283424ef"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a08bcc7d0999562b4ef2d8e0bdcfa111fe0f76fc0d3b14d42c8e93b7b90abdca"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 02 00 00 2B 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D }

	condition:
		all of them
}