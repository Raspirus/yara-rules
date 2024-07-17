rule ELASTIC_Linux_Trojan_Ngioweb_D8573802 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ngioweb (Linux.Trojan.Ngioweb)"
		author = "Elastic Security"
		id = "d8573802-f141-4fd1-b06a-605451a72465"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ngioweb.yar#L101-L119"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7454ee074812d7fa49044de8190e17b5034b3f08625f547d1b04aae4054fd81a"
		logic_hash = "b51ab7a7c26e889a4e8efc2b9883f709c17d82032b0c28ab3e30229d6f296367"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0052566dda66ae0dfa54d68f4ce03b5a2e2a442c4a18d70f16fd02303a446e66"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 40 74 38 51 51 6A 02 FF 74 24 18 FF 93 C8 00 00 00 83 C4 }

	condition:
		all of them
}