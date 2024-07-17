
rule ELASTIC_Windows_Trojan_Behinder_B9A49F4B : FILE MEMORY
{
	meta:
		description = "Webshell found in REF2924, either Behinder or Godzilla based shell in C#"
		author = "Elastic Security"
		id = "b9a49f4b-5923-420e-a9e6-9bfa05c93bbf"
		date = "2023-03-02"
		modified = "2023-06-13"
		reference = "https://www.elastic.co/security-labs/ref2924-howto-maintain-persistence-as-an-advanced-threat"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Behinder.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a50ca8df4181918fe0636272f31e19815f1b97cce6d871e15e03b0ee0e3da17b"
		logic_hash = "2303ef82e4dc5e8be87ddc4563dcd06963d17e1fbf25cf246a6c81e4e74adbcb"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "cb7856a7d3e792cc60837587fe4afc04448af74cb5ce0478a09eb129e53bf7f1"
		threat_name = "Windows.Trojan.Behinder"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$load = { 53 79 73 74 65 6D 2E 52 65 66 6C 65 63 74 69 6F 6E 2E 41 73 73 65 6D 62 6C 79 }
		$key = "e45e329feb5d925b" ascii wide

	condition:
		all of them
}