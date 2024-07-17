
rule ELASTIC_Macos_Trojan_Genieo_37878473 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Genieo (MacOS.Trojan.Genieo)"
		author = "Elastic Security"
		id = "37878473-b6f8-4cbe-ba70-31ecddf41c82"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Genieo.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0fadd926f8d763f7f15e64f857e77f44a492dcf5dc82ae965d3ddf80cd9c7a0d"
		logic_hash = "bb04ae4e0a98e0dbd0c0708d5e767306e38edf76de2671523f4bd43cbcbfefc2"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "e9760bda6da453f75e543c919c260a4560989f62f3332f28296283d4c01b62a2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 65 72 6E 61 6C 44 6F 77 6E 4C 6F 61 64 55 72 6C 46 6F 72 42 72 61 6E 64 3A 5D }

	condition:
		all of them
}