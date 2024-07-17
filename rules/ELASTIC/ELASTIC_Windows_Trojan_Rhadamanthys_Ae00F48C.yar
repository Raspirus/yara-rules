
rule ELASTIC_Windows_Trojan_Rhadamanthys_Ae00F48C : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Rhadamanthys (Windows.Trojan.Rhadamanthys)"
		author = "Elastic Security"
		id = "ae00f48c-f420-4a23-aae7-6f2bde29593c"
		date = "2023-05-05"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Rhadamanthys.yar#L54-L74"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "56b5ff5132ec1c5836223ced287d51a9ecee8d2b081f449245e136b1262a8714"
		logic_hash = "423b68717a7aead3c871e7fc744e35dad1cfd7727bfba2bdaec69fb782540380"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "8e3d13998a8e512aabf15534d61c06e0c6c51a4e8e46456538c654694310e670"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 75 30 8B 51 28 8B 41 2C 85 DB 74 03 89 53 28 85 D2 74 15 39 }
		$a2 = { 3C 65 74 50 3C 68 74 2A 3C 6E }
		$a3 = { 49 74 39 49 74 2D 49 49 74 29 49 49 74 25 49 49 74 }

	condition:
		all of them
}