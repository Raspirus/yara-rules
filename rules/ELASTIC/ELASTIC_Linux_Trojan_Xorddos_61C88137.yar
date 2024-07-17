rule ELASTIC_Linux_Trojan_Xorddos_61C88137 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "61c88137-02f6-4339-b8fc-04c72a5023aa"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L137-L155"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "479ef38fa00bb13a3aa8448aa4a4434613c6729975e193eec29fc5047f339111"
		logic_hash = "e999355606ee7389be160ce3e96c6a62d7f9132b95cfec7d9f8b1a670551e6b8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c09b31424a54e485fe5f89b4ab0a008df6e563a75191f19de12113890a4faa39"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 8B C1 8B 0C 24 8D 64 24 FC 89 0C 24 8B 4D E8 87 0C 24 96 8D 64 }

	condition:
		all of them
}