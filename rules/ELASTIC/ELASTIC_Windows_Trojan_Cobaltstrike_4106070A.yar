
rule ELASTIC_Windows_Trojan_Cobaltstrike_4106070A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Cobaltstrike (Windows.Trojan.CobaltStrike)"
		author = "Elastic Security"
		id = "4106070a-24e2-421b-ab83-67b817a9f019"
		date = "2023-05-09"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L1016-L1035"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "98789a11c06c1dfff7e02f66146afca597233c17e0d4900d6a683a150f16b3a4"
		logic_hash = "90f0209a55ca381ca58264664e04c007c799cf558f143d0c02983d4caf47bfb8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c12b919064a9cd2a603c134c5f73f6d05ffbf4cbed1e5b5246687378102e4338"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 48 8B 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 }
		$a2 = { 44 24 48 0F B7 00 66 C1 E8 0C 66 83 E0 0F 0F B7 C0 83 F8 0A }

	condition:
		all of them
}