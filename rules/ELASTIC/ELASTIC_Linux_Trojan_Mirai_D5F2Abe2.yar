rule ELASTIC_Linux_Trojan_Mirai_D5F2Abe2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "d5f2abe2-511f-474d-9292-39060bbf6feb"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c490586fbf90d360cf3b2f9e2dc943809441df3dfd64dadad27fc9f5ee96ec74"
		logic_hash = "169e7e5d1a7ea8c219464e22df9be8bc8caa2e78e1bc725674c8e0b14f6b9fc5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "475a1c92c0a938196a5a4bca708b338a62119a2adf36cabf7bc99893fee49f2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 41 56 41 89 FE 40 0F B6 FF 41 55 49 89 F5 BE 08 00 00 00 41 54 41 }

	condition:
		all of them
}