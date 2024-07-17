rule ELASTIC_Windows_Trojan_Gh0St_Ee6De6Bc : FILE MEMORY
{
	meta:
		description = "Identifies a variant of Gh0st Rat"
		author = "Elastic Security"
		id = "ee6de6bc-1648-4a77-9607-e2a211c7bda4"
		date = "2021-06-10"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Gh0st.yar#L1-L23"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ea1dc816dfc87c2340a8b8a77a4f97618bccf19ad3b006dce4994be02e13245d"
		logic_hash = "3619df974c9f4ec76899afbafdfd6839070714862c7361be476cf8f83e766e2f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "3c529043f34ad8a8692b051ad7c03206ce1aafc3a0eb8fcf7f5bcfdcb8c1b455"
		threat_name = "Windows.Trojan.Gh0st"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = ":]%d-%d-%d  %d:%d:%d" ascii fullword
		$a2 = "[Pause Break]" ascii fullword
		$a3 = "f-secure.exe" ascii fullword
		$a4 = "Accept-Language: zh-cn" ascii fullword

	condition:
		all of them
}