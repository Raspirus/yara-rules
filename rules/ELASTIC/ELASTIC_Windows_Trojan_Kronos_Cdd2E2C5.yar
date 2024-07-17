rule ELASTIC_Windows_Trojan_Kronos_Cdd2E2C5 : FILE MEMORY
{
	meta:
		description = "Strings used by the Kronos banking trojan and variants."
		author = "Elastic Security"
		id = "cdd2e2c5-17fc-4cec-aece-0b19c54faccf"
		date = "2021-02-07"
		modified = "2021-08-23"
		reference = "https://www.virusbulletin.com/virusbulletin/2014/10/paper-evolution-webinjects"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Kronos.yar#L1-L27"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "baa9cedbbe0f5689be8f8028a6537c39e9ea8b0815ad76cb98f365ca5a41653f"
		logic_hash = "a8943c5ef166446629cb46517d35db39c97a1e3efa3a7a0b5cb3d3ee9d1e6e9c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0e124d42a6741a095b66928303731e7060788bc1035b98b729ca91e4f7b6bc44"
		threat_name = "Windows.Trojan.Kronos"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "data_inject" ascii wide fullword
		$a2 = "set_filter" ascii wide fullword
		$a3 = "set_url" ascii wide fullword
		$a4 = "%ws\\%ws.cfg" ascii wide fullword
		$a5 = "D7T1H5F0F5A4C6S3" ascii wide fullword
		$a6 = "[DELETE]" ascii wide fullword
		$a7 = "Kronos" ascii wide fullword

	condition:
		4 of them
}