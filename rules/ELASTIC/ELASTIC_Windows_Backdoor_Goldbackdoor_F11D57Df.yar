
rule ELASTIC_Windows_Backdoor_Goldbackdoor_F11D57Df : FILE MEMORY
{
	meta:
		description = "Detects Windows Backdoor Goldbackdoor (Windows.Backdoor.Goldbackdoor)"
		author = "Elastic Security"
		id = "f11d57df-8dd4-481c-a557-f83ae05d53fe"
		date = "2022-04-29"
		modified = "2022-06-09"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Backdoor_Goldbackdoor.yar#L28-L51"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "45ece107409194f5f1ec2fbd902d041f055a914e664f8ed2aa1f90e223339039"
		logic_hash = "6401b215523289a3842dec6d3e016a2ca99512c5889e87cb5ff13023bb0b8e1e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fed0317d43910d962908604812c2cd1aff6e67f7e245c82b39f2ac6dc14b6edb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { C7 45 ?? 64 69 72 25 C7 45 ?? 5C 53 79 73 C7 45 ?? 74 65 6D 33 C7 45 ?? 32 5C 00 00 C7 45 ?? 2A 2E 65 78 C7 45 ?? 65 00 00 00 E8 ?? ?? ?? ?? FF D0 }
		$b = { B9 18 48 24 9D E8 ?? ?? ?? ?? FF D0 }
		$c = { B9 F8 92 FA 98 E8 ?? ?? ?? ?? FF D0 }
		$a1 = { 64 A1 30 00 00 00 53 55 56 }
		$b1 = { B9 76 DB 7A AA 6A 40 68 00 30 00 00 FF 75 ?? 50 E8 ?? ?? ?? ?? FF D0 }
		$c1 = { B9 91 51 13 EE 50 68 80 00 00 00 6A 04 50 50 ?? ?? ?? ?? ?? ?? ?? 6A 04 50 E8 ?? ?? ?? ?? FF D0 }

	condition:
		all of them
}