rule ELASTIC_Windows_Ransomware_Doppelpaymer_4Fb1A155 : BETA FILE MEMORY
{
	meta:
		description = "Identifies DOPPELPAYMER ransomware"
		author = "Elastic Security"
		id = "4fb1a155-6448-41e9-829a-e765b7c2570e"
		date = "2020-06-28"
		modified = "2021-08-23"
		reference = "https://www.crowdstrike.com/blog/doppelpaymer-ransomware-and-dridex-2/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Doppelpaymer.yar#L44-L63"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "eb041a836b2bc73312a2f87523d817d5274f3d43d3e5fe6aacfad1399c61a9de"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "f7c1bb3e9d1ad02e7c4edf8accf326330331f92a0f1184bbc19c5bde7505e545"
		threat_name = "Windows.Ransomware.Doppelpaymer"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$c1 = { 83 EC 64 8B E9 8B 44 24 ?? 8B 00 0F B7 10 83 FA 5C 75 }

	condition:
		1 of ($c*)
}