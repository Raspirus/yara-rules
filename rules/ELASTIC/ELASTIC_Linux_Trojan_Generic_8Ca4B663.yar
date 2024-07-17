
rule ELASTIC_Linux_Trojan_Generic_8Ca4B663 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Generic (Linux.Trojan.Generic)"
		author = "Elastic Security"
		id = "8ca4b663-b282-4322-833a-4c0143f63634"
		date = "2022-01-05"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Generic.yar#L181-L199"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1ddf479e504867dfa27a2f23809e6255089fa0e2e7dcf31b6ce7d08f8d88947e"
		logic_hash = "43b8cae2075f55a98b226f865d54e1c96345db0564815d849b3458d3f3ffee7f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "34e04e32ee493643cc37ff0cfb94dcbc91202f651bc2560e9c259b53a9d6acfc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 28 60 DF F2 FB B7 E7 EB 96 D1 E6 96 88 12 96 EB 8C 94 EB C7 4E }

	condition:
		all of them
}