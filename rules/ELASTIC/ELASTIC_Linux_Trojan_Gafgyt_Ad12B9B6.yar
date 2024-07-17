rule ELASTIC_Linux_Trojan_Gafgyt_Ad12B9B6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "ad12b9b6-2e66-4647-8bf3-0300f2124a97"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "f0411131acfddb40ac8069164ce2808e9c8928709898d3fb5dc88036003fe9c8"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1347-L1365"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "72a85d14eb8ab78364ea2e8b89d9409c0046b14602f4a3415d829f4985fb2de3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "46d86406f7fb25f0e240abc13e86291c56eb7468d0128fdff181f28d4f978058"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 4C 52 46 00 4B 45 46 31 4A 43 53 00 4B 45 46 31 51 45 42 00 }

	condition:
		all of them
}