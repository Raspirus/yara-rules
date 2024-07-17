rule ELASTIC_Macos_Virus_Maxofferdeal_20A0091E : FILE MEMORY
{
	meta:
		description = "Detects Macos Virus Maxofferdeal (MacOS.Virus.Maxofferdeal)"
		author = "Elastic Security"
		id = "20a0091e-a3ef-4a13-ba92-700f3583e06d"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Virus_Maxofferdeal.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b00a61c908cd06dbc26bee059ba290e7ce2ad6b66c453ea272c7287ffa29c5ab"
		logic_hash = "bb90b7e1637fd86e91763b4801a0b3bb8a1b956f328d07e96cf1b26e42b1931b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1629b34b424816040066122592e56e317b204f3d5de2f5e7f68114c7a48d99cb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { F2 E7 E7 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 A0 BC BC B8 F2 E7 E7 BF }

	condition:
		all of them
}