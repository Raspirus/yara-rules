
rule ELASTIC_Windows_Generic_Threat_D7E5Ec2D : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "d7e5ec2d-bcd1-41a3-80de-12808b9034c9"
		date = "2024-02-20"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2800-L2818"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fe711664a565566cbc710d5e678a9a30063a2db151ebec226e2abcd24c0a7e68"
		logic_hash = "4edb8cc1da81e0b9b3a8facc9a9a7d1e27dff0d2db7851d06a209beec3ccb463"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e679e6917c5055384c0492e4a8a7538b41e5239b78e2167b04fffa3693f036bb"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 83 C4 F8 89 45 FC 8B 45 FC E8 17 FE FF FF 83 FA 00 75 03 83 F8 FF 77 16 8B 45 FC E8 F1 FE FF FF 83 FA 00 75 03 83 F8 FF 77 04 33 C0 EB 02 B0 01 88 45 FB 8A 45 FB 59 59 5D C3 8D 40 00 }

	condition:
		all of them
}