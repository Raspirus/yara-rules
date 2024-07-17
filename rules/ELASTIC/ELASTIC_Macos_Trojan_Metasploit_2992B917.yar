
rule ELASTIC_Macos_Trojan_Metasploit_2992B917 : FILE MEMORY
{
	meta:
		description = "Byte sequence based on Metasploit vforkshell_reverse_tcp.rb"
		author = "Elastic Security"
		id = "2992b917-32bd-4fd8-8221-0d061239673d"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/vforkshell_reverse_tcp.rb"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L150-L169"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "10056ffb719092f83ad236a63ef6fa1f40568e500c042bd737575997bb67a8ec"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "055129bc7931d0334928be00134c109ab36825997b2877958e0ca9006b55575e"
		threat_name = "MacOS.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 6D 89 C7 52 52 68 7F 00 00 01 68 00 02 34 12 89 E3 6A }

	condition:
		all of them
}