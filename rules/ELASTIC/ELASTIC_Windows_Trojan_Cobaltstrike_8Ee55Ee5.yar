
rule ELASTIC_Windows_Trojan_Cobaltstrike_8Ee55Ee5 : FILE MEMORY
{
	meta:
		description = "Rule for wmi exec module"
		author = "Elastic Security"
		id = "8ee55ee5-67f1-4f94-ab93-62bb5cfbeee9"
		date = "2021-10-21"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CobaltStrike.yar#L949-L969"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		logic_hash = "d0cc321e15660311ae0b8e3261abe716a50a2455f82635c1b02d0a5444c8a89a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7e7ed4f00d0914ce0b9f77b6362742a9c8b93a16a6b2a62b70f0f7e15ba3a72b"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x64.o" ascii fullword
		$a2 = "z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x86.o" ascii fullword

	condition:
		1 of ($a*)
}