rule ELASTIC_Macos_Trojan_Metasploit_65A2394B : FILE MEMORY
{
	meta:
		description = "Byte sequence based on Metasploit stages vforkshell.rb"
		author = "Elastic Security"
		id = "65a2394b-0e66-4cb5-b6aa-3909120f0a94"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stages/osx/x86/vforkshell.rb"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Metasploit.yar#L192-L211"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "f01f671b0bf9fa53aa3383c88ba871742f0e55dbdae4278f440ed29f35eb1ca1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "082da76eb8da9315d495b79466366367f19170f93c0a29966858cb92145e38d7"
		threat_name = "MacOS.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a1 = { 31 DB 83 EB 01 43 53 57 53 B0 5A CD 80 72 43 83 }

	condition:
		all of them
}