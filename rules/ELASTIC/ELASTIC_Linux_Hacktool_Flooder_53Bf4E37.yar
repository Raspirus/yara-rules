
rule ELASTIC_Linux_Hacktool_Flooder_53Bf4E37 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "53bf4e37-e043-4cf2-ad2a-bc63d69585ae"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "101f2240cd032831b9c0930a68ea6f74688f68ae801c776c71b488e17bc71871"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L560-L578"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "d1aabf8067b74dac114e197722d51c4bbb9a78e6ba9b5401399930c29d55bdcc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "83e804640b0848caa532dadc33923c226a34e0272457bde00325069ded55f256"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 74 00 49 50 5F 48 44 52 49 4E 43 4C 00 57 68 61 74 20 74 68 65 20 }

	condition:
		all of them
}