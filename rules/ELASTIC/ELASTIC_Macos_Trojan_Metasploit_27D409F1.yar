
rule ELASTIC_Macos_Trojan_Metasploit_27D409F1 : FILE MEMORY
{
	meta:
		description = "Byte sequence based on Metasploit x64 shell_bind_tcp.rb"
		author = "Elastic Security"
		id = "27d409f1-80fd-4d07-815a-4741c48e0bf6"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x64/shell_bind_tcp.rb"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L171-L190"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "b757e0ab6665a3e4846c6bbe4386e9d9a730ece00a2453933ce771aec2dd716e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "43be41784449fc414c3e3bc7f4ca5827190fa10ac4cdd8500517e2aa6cce2a56"
		threat_name = "MacOS.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = { B8 61 00 00 02 6A 02 5F 6A 01 5E 48 31 D2 }

	condition:
		all of them
}