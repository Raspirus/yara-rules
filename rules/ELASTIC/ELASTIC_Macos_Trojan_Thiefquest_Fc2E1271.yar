
rule ELASTIC_Macos_Trojan_Thiefquest_Fc2E1271 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Thiefquest (MacOS.Trojan.Thiefquest)"
		author = "Elastic Security"
		id = "fc2e1271-3c96-4c93-9e3d-212782928e6e"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Thiefquest.yar#L24-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
		logic_hash = "a20c76e53874fc0fec5fd2660c63c6f1e7c1b2055cbd2a9efdfd114cd6bdda5c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "195e8f65e4ea722f0e1ba171f2ad4ded97d4bc97da38ef8ac8e54b8719e4c5ae"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 30 30 30 42 67 7B 30 30 }

	condition:
		all of them
}