
rule ELASTIC_Windows_Trojan_Bruteratel_5E383Ae0 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bruteratel (Windows.Trojan.BruteRatel)"
		author = "Elastic Security"
		id = "5e383ae0-c379-4a8b-938e-943fb1f3fd06"
		date = "2024-03-27"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_BruteRatel.yar#L152-L184"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0b506ef32f58ee2b1e5701ca8e13c67584739ab1d00ee4a0c2f532c09a15836f"
		logic_hash = "5d87ada1c609e23742c389f8153a9266c4db95be4a5e10b50979aebc993a45e0"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4a32b644ae97dfefa8766aa86cd519733ca2827a4a24d6ba5d9ac650a3559abc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "_imp_BadgerWcslen"
		$a2 = "_imp_BadgerStrcmp"
		$a3 = "_imp_BadgerDispatch"
		$a4 = "_imp_BadgerStrlen"
		$a5 = "_imp_BadgerMemset"
		$a6 = "_imp_BadgerMemcpy"
		$a7 = "_imp_BadgerWcscmp"
		$a8 = "_imp_BadgerAlloc"
		$a9 = "_imp_BadgerFree"
		$a10 = "_imp_BadgerSetdebug"
		$a11 = "_imp_BadgerGetBufferSize"
		$b1 = "__imp_Kernel32$"
		$b2 = "__imp_Ntdll$Nt"
		$b3 = "__imp_Advapi32$"
		$b4 = "__imp_NETAPI32$"

	condition:
		1 of ($a*) and 1 of ($b*)
}