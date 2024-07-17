rule ELASTIC_Macos_Trojan_Metasploit_F11Ccdac : FILE MEMORY
{
	meta:
		description = "Byte sequence based on Metasploit shell_find_port.rb"
		author = "Elastic Security"
		id = "f11ccdac-be75-4ba8-800a-179297a40792"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_find_port.rb"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L108-L127"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "fcf578d3e98b591b33cb6f4bec1b9e92a7e1a88f0b56f3c501f9089d2094289c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fbc1a5b77ed485706ae38f996cd086253ea1d43d963cb497446e5b0f3d0f3f11"
		threat_name = "MacOS.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = { 50 6A 1F 58 CD 80 66 81 7F 02 04 D2 75 EE 50 }

	condition:
		all of them
}