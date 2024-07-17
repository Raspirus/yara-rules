rule ELASTIC_Windows_Trojan_Trickbot_0114D469 : FILE MEMORY
{
	meta:
		description = "Targets systeminfo64.dll module containing functionality use to retrieve system information"
		author = "Elastic Security"
		id = "0114d469-8731-4f4f-8657-49cded5efadb"
		date = "2021-03-29"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L634-L667"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "083cb35a7064aa5589efc544ac1ed1b04ec0f89f0e60383fcb1b02b63f4117e9"
		logic_hash = "6ca8e73f758d3fa956fe53cc83abb43806359f93df05c42a58e2f394a1a3c117"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4f1fa072f4ba577d590bb8946ea9b9774aa291cb2406f13be5932e97e8e760c6"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "<user>%s</user>" wide fullword
		$a2 = "<service>%s</service>" wide fullword
		$a3 = "<users>" wide fullword
		$a4 = "</users>" wide fullword
		$a5 = "%s%s%s</general>" wide fullword
		$a6 = "<program>%s</program>" wide fullword
		$a7 = "<moduleconfig><autostart>no</autostart><limit>2</limit></moduleconfig>" ascii fullword
		$a8 = "<cpu>%s</cpu>" wide fullword
		$a9 = "<ram>%s</ram>" wide fullword
		$a10 = "</installed>" wide fullword
		$a11 = "<installed>" wide fullword
		$a12 = "<general>" wide fullword
		$a13 = "SELECT * FROM Win32_Processor" wide fullword
		$a14 = "SELECT * FROM Win32_OperatingSystem" wide fullword
		$a15 = "SELECT * FROM Win32_ComputerSystem" wide fullword

	condition:
		6 of ($a*)
}