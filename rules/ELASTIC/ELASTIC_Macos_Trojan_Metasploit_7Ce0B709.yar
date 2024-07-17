rule ELASTIC_Macos_Trojan_Metasploit_7Ce0B709 : FILE MEMORY
{
	meta:
		description = "Byte sequence based on Metasploit shell_bind_tcp.rb"
		author = "Elastic Security"
		id = "7ce0b709-1d96-407c-8eca-6af64e5bdeef"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_bind_tcp.rb"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L87-L106"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "56fc05ece464d562ff6e56247756454c940c07b03c4a4c783b2bae4d5807247a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3eb7f78d2671e16c16a6d9783995ebb32e748612d32ed4f2442e9f9c1efc1698"
		threat_name = "MacOS.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = { FF 4F E4 79 F6 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 }

	condition:
		all of them
}