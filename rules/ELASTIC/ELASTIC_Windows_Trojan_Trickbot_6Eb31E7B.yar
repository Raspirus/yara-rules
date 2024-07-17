
rule ELASTIC_Windows_Trojan_Trickbot_6Eb31E7B : FILE MEMORY
{
	meta:
		description = "Targets DomainDll module containing functionality using LDAP to retrieve credentials and configuration information"
		author = "Elastic Security"
		id = "6eb31e7b-9dc3-48ff-91fe-8c584729c415"
		date = "2021-03-30"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L845-L872"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3e3d82ea4764b117b71119e7c2eecf46b7c2126617eafccdfc6e96e13da973b1"
		logic_hash = "5b6902c8644c79bd183725f0e41bf2f7ae425bf0eb1dddea6fd1a38b77f176ba"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d145b7c95bca0dc0c46a8dff60341a21dce474edd169dd0ee5ea2396dad60b92"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "module32.dll" ascii fullword
		$a2 = "Size - %d kB" ascii fullword
		$a3 = "</moduleconfig> " ascii fullword
		$a4 = "<moduleconfig>" ascii fullword
		$a5 = "\\\\%ls\\SYSVOL\\%ls" wide fullword
		$a6 = "DomainGrabber"
		$a7 = "<autostart>yes</autostart>" ascii fullword
		$a8 = "<needinfo name=\"id\"/>" ascii fullword
		$a9 = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" wide fullword

	condition:
		5 of ($a*)
}