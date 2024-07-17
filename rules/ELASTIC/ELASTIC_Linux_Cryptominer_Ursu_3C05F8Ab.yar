
rule ELASTIC_Linux_Cryptominer_Ursu_3C05F8Ab : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Ursu (Linux.Cryptominer.Ursu)"
		author = "Elastic Security"
		id = "3c05f8ab-d1b8-424b-99b7-1fe292ae68ff"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Ursu.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d72361010184f5a48386860918052dbb8726d40e860ea0287994936702577956"
		logic_hash = "8261e4ee40131cd7df61914cd7bdf154e8a2b5fa3abd9d301436f9371253f510"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "463d4f675589e00284103ef53d0749539152bbc3772423f89a788042805b3a21"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 64 55 4C 2C 20 0A 09 30 78 33 30 32 38 36 30 37 38 32 38 37 38 }

	condition:
		all of them
}