
rule ELASTIC_Macos_Trojan_Metasploit_C7B7A90B : FILE MEMORY
{
	meta:
		description = "Byte sequence based on Metasploit stager reverse_tcp.rb"
		author = "Elastic Security"
		id = "c7b7a90b-aaf2-482d-bb95-dee20a75379e"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/reverse_tcp.rb"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L213-L232"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "d4b1f01bf8434dd69188d2ad0b376fad3a4d9c94ebe74d40f05019baf95b5496"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c4b2711417f5616ca462149882a7f33ce53dd1b8947be62fe0b818c51e4f4b2f"
		threat_name = "MacOS.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 }

	condition:
		all of them
}