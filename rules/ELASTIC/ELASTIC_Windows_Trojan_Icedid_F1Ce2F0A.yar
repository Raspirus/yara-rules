rule ELASTIC_Windows_Trojan_Icedid_F1Ce2F0A : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Icedid (Windows.Trojan.IcedID)"
		author = "Elastic Security"
		id = "f1ce2f0a-0d34-46a4-8e42-0906adf4dc1b"
		date = "2021-02-28"
		modified = "2021-08-23"
		reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_IcedID.yar#L45-L65"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b21f9afc6443548427bf83b5f93e7a54ac3af306d9d71b8348a6f146b2819457"
		logic_hash = "a1f1824a7208201616dde40bea514dfc2cdf908bd8ed24b9f96c2bcad2c8107f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1940c4bf5d8011dc7edb8dde718286554ed65f9e96fe61bfa90f6182a4b8ca9e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 8B C8 8B C6 F7 E2 03 CA 8B 54 24 14 2B D0 8B 44 24 14 89 54 }

	condition:
		all of them
}