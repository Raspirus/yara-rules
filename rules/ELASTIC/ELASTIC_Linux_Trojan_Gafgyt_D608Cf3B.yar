rule ELASTIC_Linux_Trojan_Gafgyt_D608Cf3B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "d608cf3b-c255-4a8d-9bf1-66f92eacd751"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1267-L1285"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "ad5b7d32c85adc7f778a8f4815e595b90a6f15dec048bcf97c6ab179582eb4f7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3825aa1c9cddb46fdef6abc0503b42acbca8744dd89b981a3eea8db2f86a8a76"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { FF 2F E1 7E 03 00 00 78 D8 00 00 24 00 00 00 28 00 00 00 4C }

	condition:
		all of them
}