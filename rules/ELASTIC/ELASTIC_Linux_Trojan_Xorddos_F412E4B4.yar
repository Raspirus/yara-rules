rule ELASTIC_Linux_Trojan_Xorddos_F412E4B4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "f412e4b4-adec-4011-b4b5-f5bb77b65d84"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L317-L335"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0e3a3f7973f747fcb23c72289116659c7f158c604d937d6ca7302fbab71851e9"
		logic_hash = "b4e1b193e80aa88b91255df3a5f2e45de7f23fdba4a28d3ceb12db63098e70e5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "deb9f80d032c4b3c591935c474523fd6912d7bd2c4f498ec772991504720e683"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 04 C1 E2 05 8B C0 03 C2 9C 83 C5 0F 9D 8D 6D F1 05 0C 00 }

	condition:
		all of them
}