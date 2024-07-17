
rule ELASTIC_Linux_Trojan_Rekoobe_1D307D7C : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Rekoobe (Linux.Trojan.Rekoobe)"
		author = "Elastic Security"
		id = "1d307d7c-cc84-44e5-8fa0-eda9fffb3964"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Rekoobe.yar#L81-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "00bc669f79b2903c5d9e6412050655486111647c646698f9a789e481a7c98662"
		logic_hash = "de4807353d2ba977459a1bf7f51fd815e311c0bdc5fccd5e99fd44a766f6866f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "11b1474dbdc376830bca50dbeea7f7f786c8a9b2ac51a139c4e06bed7c867121"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F8 01 75 56 83 7C 24 3C 10 75 1C BE ?? ?? 60 00 }

	condition:
		all of them
}