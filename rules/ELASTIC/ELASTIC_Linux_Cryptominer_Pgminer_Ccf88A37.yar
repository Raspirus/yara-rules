rule ELASTIC_Linux_Cryptominer_Pgminer_Ccf88A37 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Pgminer (Linux.Cryptominer.Pgminer)"
		author = "Elastic Security"
		id = "ccf88a37-2a58-40f9-8c13-f1ce218a2ec4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Pgminer.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3afc8d2d85aca61108d21f82355ad813eba7a189e81dde263d318988c5ea50bd"
		logic_hash = "77833cdb319bc8e22db2503478677d5992774105f659fe7520177a691c83aa91"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "dc82b841a7e72687921c9b14bc86218c3377f939166d11a7cccd885dad4a06e7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F6 41 83 C5 02 48 8B 5D 00 8A 0B 80 F9 2F 76 7E 41 83 FF 0A B8 0A 00 }

	condition:
		all of them
}