rule ELASTIC_Linux_Trojan_Ladvix_81Fccd74 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Ladvix (Linux.Trojan.Ladvix)"
		author = "Elastic Security"
		id = "81fccd74-465d-4f2e-b879-987bc47828dd"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "2a183f613fca5ec30dfd82c9abf72ab88a2c57d2dd6f6483375913f81aa1c5af"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Ladvix.yar#L60-L78"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "18f7ca953d22f02c1dbf03595a19b66ea582d2c1623f0042dcf15f86556ca41e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0e983107f38a6b2a739a44ab4d37c35c5a7d8217713b280a1786511089084a95"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 EA 00 00 48 8D 45 EA 48 8B 55 F0 0F B6 12 88 10 0F B7 45 EA 0F }

	condition:
		all of them
}