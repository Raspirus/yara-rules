rule ELASTIC_Linux_Hacktool_Flooder_1A4Eb229 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "1a4eb229-a194-46a5-8e93-370a40ba999b"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L400-L418"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bf6f3ffaf94444a09b69cbd4c8c0224d7eb98eb41514bdc3f58c1fb90ac0e705"
		logic_hash = "83b04e366a05a46ad67b9aaf6b9658520e119003cd65941dd69416cbc5229c30"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "de076ef23c2669512efc00ddfe926ef04f8ad939061c69131a0ef9a743639371"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F4 8B 45 E8 83 C0 01 89 45 F8 EB 0F 8B 45 E8 83 C0 01 89 45 F4 8B }

	condition:
		all of them
}