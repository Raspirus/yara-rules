
rule ELASTIC_Linux_Trojan_Merlin_Bbad69B8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Merlin (Linux.Trojan.Merlin)"
		author = "Elastic Security"
		id = "bbad69b8-e8fc-43ce-a620-793c059536fd"
		date = "2022-09-12"
		modified = "2022-10-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Merlin.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d9955487f7d08f705e41a5ff848fb6f02d6c88286a52ec837b7b555fb422d1b6"
		logic_hash = "e18079c9f018dc8d7f2fdf5c950b405f9f84ad2a5b18775dbef829fe1cb770c3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "594f385556978ef1029755cea53c3cf89ff4d6697be8769fe1977b14bbdb46d1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { DA 31 C0 BB 1F 00 00 00 EB 12 0F B6 3C 13 40 88 3C 02 40 88 }

	condition:
		all of them
}