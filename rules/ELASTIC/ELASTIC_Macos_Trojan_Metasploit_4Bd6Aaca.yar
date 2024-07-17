rule ELASTIC_Macos_Trojan_Metasploit_4Bd6Aaca : FILE MEMORY
{
	meta:
		description = "Byte sequence based on Metasploit stager x86 bind_tcp.rb"
		author = "Elastic Security"
		id = "4bd6aaca-f519-4d20-b3af-d376e0322a7e"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/bind_tcp.rb"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L234-L253"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "a3de610ced90679f6fa0dcdf7890a64369c774839ea30018a7ef6fe9289d3d17"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f4957b565d2b86c79281a0d3b2515b9a0c72f9c9c7b03dae18a3619d7e2fc3dc"
		threat_name = "MacOS.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7D }

	condition:
		all of them
}