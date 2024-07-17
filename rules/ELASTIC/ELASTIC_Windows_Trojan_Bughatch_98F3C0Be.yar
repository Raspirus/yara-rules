
rule ELASTIC_Windows_Trojan_Bughatch_98F3C0Be : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Bughatch (Windows.Trojan.Bughatch)"
		author = "Elastic Security"
		id = "98f3c0be-1327-4ba2-9320-c1a9ce90b4a4"
		date = "2022-05-09"
		modified = "2022-06-09"
		reference = "https://www.elastic.co/security-labs/bughatch-malware-analysis"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Bughatch.yar#L24-L51"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b495456a2239f3ba48e43ef295d6c00066473d6a7991051e1705a48746e8051f"
		logic_hash = "d578515fece7bd464bb09cc5ddb5caf70f4022e8b10388db689e67e662d57f66"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1ac6b1285e1925349e4e578de0b2f1cf8a008cddbb1a20eb8768b1fcc4b0c8d3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "-windowstyle hidden -executionpolicy bypass -file"
		$a2 = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"
		$a3 = "ReflectiveLoader"
		$a4 = "\\Sysnative\\"
		$a5 = "TEMP%u.CMD"
		$a6 = "TEMP%u.PS1"
		$a7 = "\\TEMP%d.%s"
		$a8 = "NtSetContextThread"
		$a9 = "NtResumeThread"

	condition:
		6 of them
}