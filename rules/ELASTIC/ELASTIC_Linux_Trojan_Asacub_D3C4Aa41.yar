rule ELASTIC_Linux_Trojan_Asacub_D3C4Aa41 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Asacub (Linux.Trojan.Asacub)"
		author = "Elastic Security"
		id = "d3c4aa41-faae-4c85-bdc5-9e09483e92fb"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Asacub.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "15044273a506f825859e287689a57c6249b01bb0a848f113c946056163b7e5f1"
		logic_hash = "3645e10e5ef8c50e5e82d749da07f5669c5162cb95aa5958ce45a414b870f619"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4961023c719599bd8da6b8a17dbe409911334c21b45d62385dd02a6dd35fd2be"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 8B 0F 83 EC 08 50 57 FF 51 54 83 C4 10 8B 8B DC FF FF FF 89 4C }

	condition:
		all of them
}