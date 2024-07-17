
rule ELASTIC_Windows_Trojan_Raccoon_58091F64 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Raccoon (Windows.Trojan.Raccoon)"
		author = "Elastic Security"
		id = "58091f64-2118-47f8-bcb2-407a3c62fa33"
		date = "2021-06-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Raccoon.yar#L22-L40"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fe09bef10b21f085e9ca411e24e0602392ab5044b7268eaa95fb88790f1a124d"
		logic_hash = "8a7388e9c3dd0dd1a79215dbabcd964a0afa883490611afb6bb500635fbfff9a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ea819b46ec08ba6b33aa19dcd6b5ad27d107a8e37f3f9eb9ff751fe8e1612f88"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 74 FF FF FF 10 8D 4D AC 53 6A 01 8D 85 60 FF FF FF 0F 43 85 60 FF }

	condition:
		all of them
}