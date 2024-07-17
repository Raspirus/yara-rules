rule ELASTIC_Linux_Hacktool_Flooder_A44Ab8Cd : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "a44ab8cd-c45e-4fe8-b96d-d4fe227f3107"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4b2068a4a666b0279358b8eb4f480d2df4c518a8b4518d0d77c6687c3bff0a32"
		logic_hash = "a0501f76aff532366292189d34a57844ba999748b94f349be2f391dfd96e2106"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0d77547064aeca6714ede98df686011c139ca720a71bcac23e40b0c02d302d6a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E0 03 48 89 45 A8 8B 45 BC 48 63 D0 48 83 EA 01 48 89 55 A0 48 }

	condition:
		all of them
}