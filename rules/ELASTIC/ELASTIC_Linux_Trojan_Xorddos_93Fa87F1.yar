rule ELASTIC_Linux_Trojan_Xorddos_93Fa87F1 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "93fa87f1-ec9d-4b3b-9c9a-a0b80963f41f"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L397-L415"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "165b4a28fd6335d4e4dfefb6c40f41f16d8c7d9ab0941ccd23e36cda931f715e"
		logic_hash = "2a1e797d4dd2599b5c67e73e3c909a1803e604edf0b6ba228713ee375ccc9b16"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3b53e54dfea89258a116dcdf4dde0b6ad583aff08d626c02a6f1bf0c76164ac7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 03 87 44 24 04 89 44 24 04 8B 04 24 8D 64 24 04 8B 00 9C 83 }

	condition:
		all of them
}