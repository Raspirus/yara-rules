
rule ELASTIC_Linux_Hacktool_Flooder_4Bcea1C4 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "4bcea1c4-de08-4526-8d31-89c5512f07af"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L360-L378"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9a564d6b29d2aaff960e6f84cd0ef4c701fefa2a62e2ea690106f3fdbabb0d71"
		logic_hash = "76019729a3a33fc04ff983f38b4fbf174a66da7ffc05cd07eb93e3cd5aecaaa2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e859966e8281e024c82dedd5bd237ab53af28a0cb21d24daa456e5cd1186c352"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 50 FF 48 8B 45 C0 48 01 D0 0F B6 00 3C 0A 74 22 48 8B 45 C0 48 }

	condition:
		all of them
}