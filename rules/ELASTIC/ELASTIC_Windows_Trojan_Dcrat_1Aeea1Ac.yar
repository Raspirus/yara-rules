rule ELASTIC_Windows_Trojan_Dcrat_1Aeea1Ac : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Dcrat (Windows.Trojan.DCRat)"
		author = "Elastic Security"
		id = "1aeea1ac-69b9-4cc6-91af-18b7a79f35ce"
		date = "2022-01-15"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_DCRat.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "6163e04a40ed52d5e94662131511c3ae08d473719c364e0f7de60dff7fa92cf7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fc67d76dc916b7736de783aa245483381a8fe071c533f3761e550af80a873fe9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "havecamera" ascii fullword
		$a2 = "timeout 3 > NUL" wide fullword
		$a3 = "START \"\" \"" wide fullword
		$a4 = "L2Mgc2NodGFza3MgL2NyZWF0ZSAvZiAvc2Mgb25sb2dvbiAvcmwgaGlnaGVzdCAvdG4g" wide fullword
		$a5 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA==" wide fullword
		$b1 = "DcRatByqwqdanchun" ascii fullword
		$b2 = "DcRat By qwqdanchun1" ascii fullword

	condition:
		5 of ($a*) or 1 of ($b*)
}