
rule ELASTIC_Linux_Hacktool_Flooder_F434A3Fb : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "f434a3fb-e5fd-4749-8e53-fc6c80ee5406"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L160-L178"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ba895a9c449bf9bf6c092df88b6d862a3e8ed4079ef795e5520cb163a45bcdb4"
		logic_hash = "11b173f73b87f50775be50c6b4528bd9b148ea4266297aec76ae126cab0facb0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b74e55c56a063e14608f7e8f578cc3c74ec57954df39e63e49b60c0055725d51"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C0 48 01 45 F8 48 83 45 E8 02 83 6D E4 01 83 7D E4 00 7F E3 48 8B }

	condition:
		all of them
}