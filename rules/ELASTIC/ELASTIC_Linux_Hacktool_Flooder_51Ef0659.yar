rule ELASTIC_Linux_Hacktool_Flooder_51Ef0659 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "51ef0659-2691-4558-bff8-fce614f10ab9"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L420-L438"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b7a2bc75dd9c44c38b2a6e4e7e579142ece92a75b8a3f815940c5aa31470be2b"
		logic_hash = "26dd95cb1cdaec10d408e294a3baca85d741cf5e56649cdcc79ef7216e4cb440"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "41f517a19a3c4dc412200b683f4902a656f3dcfdead8b8292e309413577c3850"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E0 03 48 89 45 B0 8B 45 9C 48 63 D0 48 83 EA 01 48 89 55 B8 48 }

	condition:
		all of them
}