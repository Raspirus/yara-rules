
rule ELASTIC_Linux_Trojan_Getshell_213D4D69 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Getshell (Linux.Trojan.Getshell)"
		author = "Elastic Security"
		id = "213d4d69-5660-468d-a98c-ff3eef604b1e"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "05fc4dcce9e9e1e627ebf051a190bd1f73bc83d876c78c6b3d86fc97b0dfd8e8"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Getshell.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "2075def88b31ac32e44c270ab20273c8b91f37e25a837c0353f76bcf431cdcb3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "60e385e4c5eb189785bc14d39bf8a22c179e4be861ce3453fbcf4d367fc87c90"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { EC 01 00 00 00 EB 3C 8B 45 EC 48 98 48 C1 E0 03 48 03 45 D0 48 }

	condition:
		all of them
}