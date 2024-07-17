
rule ELASTIC_Windows_Trojan_Raccoon_Af6Decc6 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Raccoon (Windows.Trojan.Raccoon)"
		author = "Elastic Security"
		id = "af6decc6-f917-4a80-b96d-1e69b8f8ebe0"
		date = "2021-06-28"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Raccoon.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fe09bef10b21f085e9ca411e24e0602392ab5044b7268eaa95fb88790f1a124d"
		logic_hash = "50ec446e8fd51129c7333c943dfe62db099fe1379530441f6b102fcbe3bc0dbd"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f9314a583040e4238aab7712ac16d7638a3b7c9194cbcf2ea9b4516c228c546b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "A:\\_Work\\rc-build-v1-exe\\json.hpp" wide fullword
		$a2 = "\\stealler\\json.hpp" wide fullword

	condition:
		any of them
}