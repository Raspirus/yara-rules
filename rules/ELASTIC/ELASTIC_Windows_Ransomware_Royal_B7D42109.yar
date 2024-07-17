
rule ELASTIC_Windows_Ransomware_Royal_B7D42109 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Royal (Windows.Ransomware.Royal)"
		author = "Elastic Security"
		id = "b7d42109-f327-4ec3-86ac-d1ebb9478860"
		date = "2022-11-04"
		modified = "2022-12-20"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Royal.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "491c2b32095174b9de2fd799732a6f84878c2e23b9bb560cd3155cbdc65e2b80"
		logic_hash = "06f4a1487e97e0b8c1f5df380ab4f90b37ef0a508aba7dac272c16c8371d8143"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ff518f25b39b02769b67c437f38958d14e4e8f50b91f4c73591203da297a5d2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "Try Royal today and enter the new era of data security" ascii fullword
		$a2 = "If you are reading this, it means that your system were hit by Royal ransomware." ascii fullword
		$a3 = "http://royal"
		$a4 = "\\README.TXT" wide fullword

	condition:
		all of them
}