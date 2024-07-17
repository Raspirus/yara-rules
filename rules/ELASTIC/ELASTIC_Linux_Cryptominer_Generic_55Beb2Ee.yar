rule ELASTIC_Linux_Cryptominer_Generic_55Beb2Ee : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "55beb2ee-7306-4134-a512-840671cc4490"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L661-L679"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "edda1c6b3395e7f14dd201095c1e9303968d02c127ff9bf6c76af6b3d02e80ad"
		logic_hash = "8a31b4866100b35d559d50f5db6f80d51bced93f9aac3f0d2d1de71ba692a3c5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "707a1478f86da2ec72580cfe4715b466e44c345deb6382b8dc3ece4e3935514d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 24 FC 00 00 00 8B 84 24 C0 00 00 00 0F 29 84 24 80 00 00 00 0F 11 94 24 C4 00 }

	condition:
		all of them
}