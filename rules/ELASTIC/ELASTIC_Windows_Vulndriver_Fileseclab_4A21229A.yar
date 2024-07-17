
rule ELASTIC_Windows_Vulndriver_Fileseclab_4A21229A : FILE
{
	meta:
		description = "Detects Windows Vulndriver Fileseclab (Windows.VulnDriver.Fileseclab)"
		author = "Elastic Security"
		id = "4a21229a-8847-4909-b3cd-69b4078a4825"
		date = "2024-03-05"
		modified = "2024-03-21"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Vulndriver_Fileseclab.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ae55a0e93e5ef3948adecf20fa55b0f555dcf40589917a5bfbaa732075f0cc12"
		logic_hash = "bac78186f3d46c6765bacaf6a324ff94e449261cefe2594cb38c4cc25db1f0de"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "dcbdbd375bae3d9206a82bbffa9f803492ed9588333075d93fad4b9f3261be7b"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "filwfp.sys"
		$a2 = "filnk.sys"
		$a3 = { 5C 00 64 00 65 00 76 00 69 00 63 00 65 00 5C 00 66 00 69 00 6C 00 77 00 66 00 70 00 }
		$a4 = { 5C 00 64 00 65 00 76 00 69 00 63 00 65 00 5C 00 66 00 69 00 6C 00 77 00 66 00 70 00 }
		$b1 = { 31 00 2C 00 20 00 30 00 2C 00 20 00 30 00 2C 00 20 00 }
		$b2 = { 32 00 2C 00 20 00 30 00 2C 00 20 00 30 00 2C 00 20 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and 1 of ($a*) and 1 of ($b*)
}