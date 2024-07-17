
rule ELASTIC_Linux_Hacktool_Flooder_B1Ca2Abd : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "b1ca2abd-b8ab-435d-85b6-a1c93212e492"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L320-L338"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1d88971f342e4bc4e6615e42080a3b6cec9f84912aa273c36fc46aaf86ff6771"
		logic_hash = "05b906a9823bf9ba25ba1ed490beb8f338429cbc744ca230c5c4cbb41ab9f140"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "214c9dedf34b2c8502c6ef14aff5727ac5a2941e1a8278a48d34fea14d584a1a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C4 48 89 E0 48 83 C0 07 48 C1 E8 03 48 C1 E0 03 48 89 45 B0 C7 45 AC 14 00 }

	condition:
		all of them
}