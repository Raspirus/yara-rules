
rule ELASTIC_Windows_Trojan_Havoc_Ffecc8Af : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Havoc (Windows.Trojan.Havoc)"
		author = "Elastic Security"
		id = "ffecc8af-4a64-4252-b7ca-3316d27c3942"
		date = "2024-04-29"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Havoc.yar#L78-L107"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "495d323651c252e38814b77b9c6c913b9489e769252ac8bbaf8432f15e0efe44"
		logic_hash = "c9da6215db1de91a6cd52dd6558dc5a60bbd69abc6fa0db8714f001cdae20ddb"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "d09b0519d518b741cec7f6e42efaa657410edd36d027f54e515be510b33fa821"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$commands_table = { 0B 00 00 00 00 00 00 00 [8] 64 00 00 00 00 00 00 00 [8] 15 00 00 00 00 00 00 00 [8] 10 10 00 00 00 00 00 00 [8] 0C 00 00 00 00 00 00 00 [8] 0F 00 00 00 00 00 00 00 [8] 14 00 00 00 00 00 00 00 [8] 01 20 00 00 00 00 00 00 [8] 03 20 00 00 00 00 00 00 [8] C4 09 00 00 00 00 00 00 [8] CE 09 00 00 00 00 00 00 [8] D8 09 00 00 00 00 00 00 [8] 34 08 00 00 00 00 00 00 [8] 16 00 00 00 00 00 00 00 [8] 18 00 00 00 00 00 00 00 [8] 1A 00 00 00 00 00 00 00 [8] 28 00 00 00 00 00 00 00 [8] E2 09 00 00 00 00 00 00 [8] EC 09 00 00 00 00 00 00 [8] F6 09 00 00 00 00 00 00 [8] 00 0A 00 00 00 00 00 00 [8] 5C 00 00 00 00 00 00 00 }
		$hash_ldrloaddll = { 43 6A 45 9E }
		$hash_ldrgetprocedureaddress = { B6 6B CE FC }
		$hash_ntaddbootentry = { 76 C7 FC 8C }
		$hash_ntallocatevirtualmemory = { EC B8 83 F7 }
		$hash_ntfreevirtualmemory = { 09 C6 02 28 }
		$hash_ntunmapviewofsection = { CD 12 A4 6A }
		$hash_ntwritevirtualmemory = { 92 01 17 C3 }
		$hash_ntsetinformationvirtualmemory = { 39 C2 6A 94 }
		$hash_ntqueryvirtualmemory = { 5D E8 C0 10 }
		$hash_ntopenprocesstoken = { 99 CA 0D 35 }
		$hash_ntopenthreadtoken = { D2 47 33 80 }

	condition:
		$commands_table and 4 of ($hash_*)
}