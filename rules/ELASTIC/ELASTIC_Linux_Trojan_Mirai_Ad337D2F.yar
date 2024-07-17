
rule ELASTIC_Linux_Trojan_Mirai_Ad337D2F : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "ad337d2f-d4ac-42a7-9d2e-576fe633fa16"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "012b717909a8b251ec1e0c284b3c795865a32a1f4b79706d2254a4eb289c30a7"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L1702-L1720"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "dba630c1deb00b0dbd9f895a9b93393bc634150c8f32527b02d8dd71dc806e7d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "67cbcb8288fe319c3b8f961210748f7cea49c2f64fc2f1f55614d7ed97a86238"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 01 75 14 80 78 FF 2F 48 8D 40 FF 0F 94 C2 48 39 D8 77 EB 84 D2 }

	condition:
		all of them
}