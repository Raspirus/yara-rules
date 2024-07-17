
rule ELASTIC_Linux_Cryptominer_Generic_6A4F4255 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "6a4f4255-d202-48b7-96ae-cb7211dcbea3"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L161-L179"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8cfc38db2b860efcce5da40ce1e3992f467ab0b7491639d68d530b79529cda80"
		logic_hash = "133290dc7423174bb3b41b152bab038d118b47baaca52705b66fd9be01692a03"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0ed37d7eccd4e36b954824614b976e1371c3b2ffe318345d247198d387a13de6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FD 48 8D 5D 01 4C 8D 14 1B 48 C1 E3 05 4C 01 EB 4D 8D 7A FF F2 0F }

	condition:
		all of them
}