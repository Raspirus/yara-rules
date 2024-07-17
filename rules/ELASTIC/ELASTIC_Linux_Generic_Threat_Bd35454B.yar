rule ELASTIC_Linux_Generic_Threat_Bd35454B : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "bd35454b-a0dd-4925-afae-6416f3695826"
		date = "2024-02-21"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L841-L860"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cd729507d2e17aea23a56a56e0c593214dbda4197e8a353abe4ed0c5fbc4799c"
		logic_hash = "d3619cdb002b4ac7167716234058f949623c42a64614f5eb7956866b68fff5e4"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "721aa441a2567eab29c9bc76f12d0fdde8b8a124ca5a3693fbf9821f5b347825"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 6D 61 69 6E 2E 65 6E 63 72 79 70 74 5F 66 69 6C 65 }
		$a2 = { 57 68 61 74 20 67 75 61 72 61 6E 74 65 65 73 3F }

	condition:
		all of them
}