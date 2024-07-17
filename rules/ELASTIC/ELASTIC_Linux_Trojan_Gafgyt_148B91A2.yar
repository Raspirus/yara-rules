rule ELASTIC_Linux_Trojan_Gafgyt_148B91A2 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "148b91a2-ed51-4c2d-9d15-6a48d9ea3e0a"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L792-L810"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d5b2bde0749ff482dc2389971e2ac76c4b1e7b887208a538d5555f0fe6984825"
		logic_hash = "1a974c0882c2d088c978a52e5b535807c86f117cf2f05c40c084e849b1849f5b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0f75090ed840f4601df4e43a2f49f2b32585213f3d86d19fb255d79c21086ba3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { C6 45 DB FC EB 04 C6 45 DB FE 0F B6 45 DB 88 45 FF 48 8D 75 FF 8B }

	condition:
		all of them
}