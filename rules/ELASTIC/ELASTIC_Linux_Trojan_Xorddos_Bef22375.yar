
rule ELASTIC_Linux_Trojan_Xorddos_Bef22375 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Xorddos (Linux.Trojan.Xorddos)"
		author = "Elastic Security"
		id = "bef22375-0a71-4f5b-bfd1-e2e718b5c36f"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Xorddos.yar#L477-L495"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f47baf48deb71910716beab9da1b1e24dc6de9575963e238735b6bcedfe73122"
		logic_hash = "3991ebdb310338516d5fdd137ba2ac63dc870337785a31d59dcad49135f190e5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0128e8725a0949dd23c23addc1158d28c334cfb040aad2b8f8d58f39720c41ef"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C5 35 9D 8D 6D CB 8B 12 9C 83 C5 17 9D 8D 6D E9 6A 04 F7 14 24 FF }

	condition:
		all of them
}