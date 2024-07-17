rule ELASTIC_Macos_Trojan_Metasploit_D9B16F4C : FILE MEMORY
{
	meta:
		description = "Byte sequence based on Metasploit vforkshell_bind_tcp.rb"
		author = "Elastic Security"
		id = "d9b16f4c-8cc9-42ce-95fa-8db06df9d582"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/vforkshell_bind_tcp.rb"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L129-L148"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "8e082878fb52f6314ec8c725dd279447ee8a0fc403c47ffd997712adb496e7c3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cf5cfc372008ae98a0958722a7b23f576d6be3b5b07214d21594a48a87d92fca"
		threat_name = "MacOS.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7E 00 00 00 89 C6 52 52 52 68 00 02 34 12 89 E3 6A }

	condition:
		all of them
}