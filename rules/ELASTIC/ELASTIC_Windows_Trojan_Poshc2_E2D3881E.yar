rule ELASTIC_Windows_Trojan_Poshc2_E2D3881E : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Poshc2 (Windows.Trojan.PoshC2)"
		author = "Elastic Security"
		id = "e2d3881e-d849-4ec8-a560-000a9b29814f"
		date = "2023-03-29"
		modified = "2023-04-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_PoshC2.yar#L1-L26"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7a718a4f74656346bd9a2e29e008705fc2b1c4d167a52bd4f6ff10b3f2cd9395"
		logic_hash = "4f3e2a9f22826a155a3007193a0f75a5fde6e423734a60f30628ea3bb33d3457"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "30a9161077a90068acf756dcc2354bd04186f87717e32cccdcacc9521c41ddde"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Sharp_v4_x64.dll"
		$a2 = "Sharp_v4_x86_dll"
		$a3 = "Posh_v2_x64_Shellcode" wide
		$a4 = "Posh_v2_x86_Shellcode" wide
		$b1 = "kill-implant" wide
		$b2 = "run-dll-background" wide
		$b3 = "run-exe-background" wide
		$b4 = "TVqQAAMAAAAEAAAA"

	condition:
		1 of ($a*) and 1 of ($b*)
}