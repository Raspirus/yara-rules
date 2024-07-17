
rule ELASTIC_Macos_Trojan_Metasploit_768Df39D : FILE MEMORY
{
	meta:
		description = "Byte sequence based on Metasploit shell_reverse_tcp.rb"
		author = "Elastic Security"
		id = "768df39d-7ee9-454e-82f8-5c7bd733c61a"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_reverse_tcp.rb"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L66-L85"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "140ba93d57b27325f66b36132ecaab205663e3e582818baf377e050802c8d152"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d45230c1111bda417228e193c8657d2318b1d2cddfbd01c5c6f2ea1d0be27a46"
		threat_name = "MacOS.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = { FF 4F E8 79 F6 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 }

	condition:
		all of them
}