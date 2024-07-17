
rule ELASTIC_Windows_Trojan_Trickbot_D2110921 : FILE MEMORY
{
	meta:
		description = "Targets shareDll64.dll module containing functionality use to spread Trickbot across local networks"
		author = "Elastic Security"
		id = "d2110921-b957-49b7-8a26-4c0b7d1d58ad"
		date = "2021-03-29"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Trickbot.yar#L603-L632"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "05ef40f7745db836de735ac73d6101406e1d9e58c6b5f5322254eb75b98d236a"
		logic_hash = "39ef17836f29c358f596e0047d582b5f1d1af523c8f6354ac8a783eda9969554"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "55dbbcbc77ec51a378ad2ba8d56cb0811d23b121cacd037503fd75d08529c5b5"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "module64.dll" ascii fullword
		$a2 = "Size - %d kB" ascii fullword
		$a3 = "%s - FAIL" wide fullword
		$a4 = "%s - SUCCESS" wide fullword
		$a5 = "ControlSystemInfoService" ascii fullword
		$a6 = "<moduleconfig><autostart>yes</autostart></moduleconfig>" ascii fullword
		$a7 = "Copy: %d" wide fullword
		$a8 = "Start sc 0x%x" wide fullword
		$a9 = "Create sc 0x%x" wide fullword
		$a10 = "Open sc %d" wide fullword
		$a11 = "ServiceInfoControl" ascii fullword

	condition:
		3 of ($a*)
}