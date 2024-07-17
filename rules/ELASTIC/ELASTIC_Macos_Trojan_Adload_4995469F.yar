
rule ELASTIC_Macos_Trojan_Adload_4995469F : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Adload (MacOS.Trojan.Adload)"
		author = "Elastic Security"
		id = "4995469f-9810-4c1f-b9bc-97e951fe9256"
		date = "2021-10-04"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Adload.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "6464ca7b36197cccf0dac00f21c43f0cb09f900006b1934e2b3667b367114de5"
		logic_hash = "cceb804a11b93b0e3f491016c47a823d9e6a31294c3ed05d4404601323b30993"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9b7e7c76177cc8ca727df5039a5748282f5914f2625ec1f54d67d444f92f0ee5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 49 8B 77 08 49 8B 4F 20 48 BF 89 88 88 88 88 88 88 88 48 89 C8 48 F7 E7 48 C1 }

	condition:
		all of them
}