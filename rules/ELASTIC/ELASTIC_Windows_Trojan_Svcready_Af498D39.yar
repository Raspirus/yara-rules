rule ELASTIC_Windows_Trojan_Svcready_Af498D39 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Svcready (Windows.Trojan.SVCReady)"
		author = "Elastic Security"
		id = "af498d39-6ae8-46de-ad6c-81b346d80139"
		date = "2022-06-12"
		modified = "2022-07-18"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SVCReady.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "08e427c92010a8a282c894cf5a77a874e09c08e283a66f1905c131871cc4d273"
		logic_hash = "e3520103064cf82cd1747f8889667929d23466c9febfda7e4968a3679db97d71"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6e30d9977698c7864a8c264a7fe8c9a558f6e51dda9c887bda94261ce187645f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "RunPEDllNative::HookNtCreateUserProcess fail: targetMapping.valid" ascii fullword
		$a2 = "Section Mapping error:Process=0x%x Section [%s] res[0x%x] != va[0x%x] Status:%u" ascii fullword
		$a3 = "%s - %I64d < %I64d > %I64d clicks, %I64d pixels, ready=%i" ascii fullword
		$a4 = "Svc:windowThreadRunner done" ascii fullword
		$a5 = "svc commonMain" ascii fullword

	condition:
		4 of them
}