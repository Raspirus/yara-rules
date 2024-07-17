rule ELASTIC_Windows_Trojan_Sysjoker_1Ef19A12 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Sysjoker (Windows.Trojan.SysJoker)"
		author = "Elastic Security"
		id = "1ef19a12-ee26-47da-8d65-272f6749b476"
		date = "2022-02-17"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_SysJoker.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "61df74731fbe1eafb2eb987f20e5226962eeceef010164e41ea6c4494a4010fc"
		logic_hash = "25bd58d546549d208f9f95f4c27d1e58f86f87750dae1e293544cc92b25f8b32"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "9123af8b8b27ebfb9199e70eb34d43378b1796319186d5d848d650a8be02d5d5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "';Write-Output \"Time taken : $((Get - Date).Subtract($start_time).Seconds) second(s)\"" ascii fullword
		$a2 = "powershell.exe Expand-Archive -LiteralPath '" ascii fullword
		$a3 = "powershell.exe Invoke-WebRequest -Uri '" ascii fullword
		$a4 = "\\recoveryWindows.zip" ascii fullword

	condition:
		3 of them
}