rule ELASTIC_Linux_Trojan_Mobidash_8679E1Cb : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mobidash (Linux.Trojan.Mobidash)"
		author = "Elastic Security"
		id = "8679e1cb-407e-4554-8ef5-ece5110735c6"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mobidash.yar#L179-L196"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "6055ac4800397f6582e60cdf15fa74584986e1e7cf49a541b0ec746445834819"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7e517bf9e036410acf696c85bd39c720234b64aab8c5b329920a64f910c72c92"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 1C 89 F0 5B 5E 5F 5D C3 8D 76 00 8B 44 24 34 83 C6 01 8D 7C }

	condition:
		all of them
}