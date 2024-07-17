
rule ELASTIC_Linux_Trojan_Tsunami_D9E6B88E : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "d9e6b88e-256c-4e9d-a411-60b477b70446"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a4ac275275e7be694a200fe6c5c5746256398c109cf54f45220637fe5d9e26ba"
		logic_hash = "979d2ae62efca0f719ed1db2ff832dc9a0aa0347dcd50ccede29ec35cba6d296"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8fc61c0754d1a8b44cefaf2dbd937ffa0bb177d98b071347d2f9022181555b7a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 04 02 01 20 03 20 02 C9 07 40 4E 00 60 01 C0 04 17 B6 92 07 }

	condition:
		all of them
}