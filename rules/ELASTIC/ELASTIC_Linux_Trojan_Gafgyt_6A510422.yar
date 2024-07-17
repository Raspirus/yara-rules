rule ELASTIC_Linux_Trojan_Gafgyt_6A510422 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "6a510422-3662-4fdb-9c03-0101f16e87cd"
		date = "2021-06-28"
		modified = "2021-09-16"
		reference = "14cc92b99daa0c91aa09d9a7996ee5549a5cacd7be733960b2cf3681a7c2b628"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L1207-L1225"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "4384536817bf5df223d4cf145892b7714f2dbd1748930b6cd43152d4e35c9e56"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8ee116ff41236771cdc8dc4b796c3b211502413ae631d5b5aedbbaa2eccc3b75"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 0B E5 24 30 1B E5 2C 30 0B E5 1C 00 00 EA 18 30 1B E5 00 30 }

	condition:
		all of them
}