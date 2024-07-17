rule ELASTIC_Linux_Generic_Threat_Cd9Ce063 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "cd9ce063-a33b-4771-b7c0-7342d486e15a"
		date = "2024-02-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L761-L779"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "485581520dd73429b662b73083d504aa8118e01c5d37c1c08b21a5db0341a19d"
		logic_hash = "ba070c2147028cad4be1c139b16a770c9d9854456d073373a93ed0b213f7b34c"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "e090bd44440e912d04de390c240ca18265bcf49e34f6689b3162e74d2fd31ba4"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 2C 2A 73 74 72 75 63 74 20 7B 20 46 20 75 69 6E 74 70 74 72 3B 20 2E 61 75 74 6F 74 6D 70 5F 32 36 20 2A 74 6C 73 2E 43 6F 6E 6E 20 7D }

	condition:
		all of them
}