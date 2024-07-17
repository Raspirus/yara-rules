rule ELASTIC_Windows_Hacktool_Sharpapplocker_9645Cf22 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Sharpapplocker (Windows.Hacktool.SharpAppLocker)"
		author = "Elastic Security"
		id = "9645cf22-f9b3-45ff-a5d8-513c59ad3d53"
		date = "2022-11-20"
		modified = "2023-01-11"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_SharpAppLocker.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0f7390905abc132889f7b9a6d5b42701173aafbff5b8f8882397af35d8c10965"
		logic_hash = "cb72ecf7715b288acddac51dab091d84c64e3bd30276cba38a0d773e6693875c"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "720a96f7baa8af4e6189709ee906350c291e175ac861c83d425b235d9217bb32"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$guid = "FE102D27-DEC4-42E2-BF69-86C79E08B67D" ascii wide nocase
		$print_str0 = "[+] Output written to:" ascii wide fullword
		$print_str1 = "[!] You can only select one Policy at the time." ascii wide fullword
		$print_str2 = "SharpAppLocker.exe --effective --allow --rules=\"FileHashRule,FilePathRule\" --outfile=\"C:\\Windows\\Tasks\\Rules.json\"" ascii wide fullword

	condition:
		$guid or all of ($print_str*)
}