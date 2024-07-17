rule ELASTIC_Linux_Hacktool_Earthworm_4De7B584 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Earthworm (Linux.Hacktool.Earthworm)"
		author = "Elastic Security"
		id = "4de7b584-d25f-414b-bdd5-45f3672a62d8"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Earthworm.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9d61aabcf935121b4f7fc6b0d082d7d6c31cb43bf253a8603dd46435e66b7955"
		logic_hash = "019b2504df192e673f96a86464bb5e8ba5e89190e51bfe7d702753f76c00b979"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "af2dc166ad5bbd3e312338a3932134c33c33c124551e7828eeef299d89419d21"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 73 6F 63 6B 73 64 20 2C 20 72 63 73 6F 63 6B 73 20 2C 20 72 73 }

	condition:
		all of them
}