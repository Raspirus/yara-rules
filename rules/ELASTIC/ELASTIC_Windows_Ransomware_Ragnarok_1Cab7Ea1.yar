rule ELASTIC_Windows_Ransomware_Ragnarok_1Cab7Ea1 : BETA FILE MEMORY
{
	meta:
		description = "Identifies RAGNAROK ransomware"
		author = "Elastic Security"
		id = "1cab7ea1-8d26-4478-ab41-659c193b5baa"
		date = "2020-05-03"
		modified = "2021-08-23"
		reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Ragnarok.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "8bae3ea4304473209fc770673b680154bf227ce30f6299101d93fe830da0fe91"
		score = 75
		quality = 73
		tags = "BETA, FILE, MEMORY"
		fingerprint = "e2a8eabb08cb99c4999e05a06d0d0dce46d7e6375a72a6a5e69d718c3d54a3ad"
		threat_name = "Windows.Ransomware.Ragnarok"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$c1 = ".ragnarok" ascii wide fullword

	condition:
		1 of ($c*)
}