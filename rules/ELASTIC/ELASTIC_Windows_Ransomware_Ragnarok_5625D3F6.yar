rule ELASTIC_Windows_Ransomware_Ragnarok_5625D3F6 : BETA FILE MEMORY
{
	meta:
		description = "Identifies RAGNAROK ransomware"
		author = "Elastic Security"
		id = "5625d3f6-7071-4a09-8ddf-faa2d081b539"
		date = "2020-05-03"
		modified = "2021-08-23"
		reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Ragnarok.yar#L73-L95"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "8c22cf9dfbeba7391f6d2370c88129650ef4c778464e676752de1d0fd9c5b34e"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "5c0a4e2683991929ff6307855bf895e3f13a61bbcc6b3c4b47d895f818d25343"
		threat_name = "Windows.Ransomware.Ragnarok"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$b1 = "prv_ip" ascii fullword
		$b2 = "%i.%i.%i" ascii fullword
		$b3 = "pub_ip" ascii fullword
		$b4 = "cometosee" ascii fullword

	condition:
		all of ($b*)
}