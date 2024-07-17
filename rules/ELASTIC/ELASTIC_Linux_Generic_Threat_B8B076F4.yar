
rule ELASTIC_Linux_Generic_Threat_B8B076F4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "b8b076f4-c64a-400b-80cb-5793c97ad033"
		date = "2024-02-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L781-L799"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4496e77ff00ad49a32e090750cb10c55e773752f4a50be05e3c7faacc97d2677"
		logic_hash = "37f3be4cbda4a93136d66e32d7245d4c962a9fe1c98fb0325f42a1d16d6d9415"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f9c6c055e098164d0add87029d03aec049c4bed2c4643f9b4e32dd82f596455c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 48 81 EC C0 00 00 00 48 89 AC 24 B8 00 00 00 48 8D AC 24 B8 00 00 00 44 0F 11 7C 24 2E 44 0F 11 7C 24 2F 44 0F 11 7C 24 3F 44 0F 11 7C 24 4F 44 0F 11 7C 24 5F 48 8B 94 24 C8 00 00 00 48 89 54 }

	condition:
		all of them
}