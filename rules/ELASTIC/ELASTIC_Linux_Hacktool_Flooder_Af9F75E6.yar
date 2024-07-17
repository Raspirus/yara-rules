rule ELASTIC_Linux_Hacktool_Flooder_Af9F75E6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "af9f75e6-9a9b-4e03-9c76-8c0c9f07c8b1"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L100-L118"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bf6f3ffaf94444a09b69cbd4c8c0224d7eb98eb41514bdc3f58c1fb90ac0e705"
		logic_hash = "b74f5fad3c7219038e51eb4fa12fb9d55d7f65a9f4bab0adff8609fabb0afdab"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f6e7d6e9c03c8ce3e14b214fe268e7aab2e15c1b4378fe253021497fb9a884e6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C4 48 89 E0 48 83 C0 07 48 C1 E8 03 48 C1 E0 03 48 89 45 C0 C7 45 B4 14 00 }

	condition:
		all of them
}