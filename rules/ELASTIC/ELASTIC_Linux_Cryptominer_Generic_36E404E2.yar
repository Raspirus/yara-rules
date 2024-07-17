
rule ELASTIC_Linux_Cryptominer_Generic_36E404E2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "36e404e2-be7c-40dc-b861-8ab929cad019"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L861-L879"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "59a1d8aa677739f2edbb8bd34f566b31f19d729b0a115fef2eac8ab1d1acc383"
		logic_hash = "d38cc5714721c0b00cfa47cb9828fd76ff57ec8180e5cfe1fec67a092dd87904"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7268b94d67f586ded78ad3a52b23a81fd4edb866fedd0ab1e55997f1bbce4c72"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 61 6C 73 65 20 70 6F 73 69 74 69 76 65 29 1B 5B 30 6D 00 44 45 }

	condition:
		all of them
}