rule ELASTIC_Linux_Generic_Threat_23D54A0E : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "23d54a0e-f2e2-443e-832c-d57146350eb6"
		date = "2024-01-18"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L166-L185"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a2b54f789a1c4cbed13e0e2a5ab61e0ce5bb42d44fe52ad4b7dd3da610045257"
		logic_hash = "7e52eaf9c49bd6cbdb89b0c525b448864e1ea55d00bc052898613174fe5956cc"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "4ff521192e2061af868b9403479680fd77d1dc71f181877a36329f63e91b7c66"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 29 2B 2F 30 31 3C 3D 43 4C 4D 50 53 5A 5B }
		$a2 = { 61 64 78 61 65 73 61 76 78 62 69 6E 63 67 6F 64 69 72 64 6E 73 65 6E 64 66 69 6E 66 6D 61 66 74 70 67 63 20 67 70 20 69 6E 20 69 6E 74 6D 61 70 6E 69 6C 6F 62 6A 70 63 3D 70 74 72 73 65 74 73 68 61 73 73 68 74 63 70 75 64 70 }

	condition:
		all of them
}