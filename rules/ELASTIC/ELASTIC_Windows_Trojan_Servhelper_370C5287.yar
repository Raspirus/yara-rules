rule ELASTIC_Windows_Trojan_Servhelper_370C5287 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Servhelper (Windows.Trojan.ServHelper)"
		author = "Elastic Security"
		id = "370c5287-0e2f-4113-95b6-53d31671fa46"
		date = "2022-03-24"
		modified = "2022-04-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_ServHelper.yar#L22-L40"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "05d183430a7afe16a3857fc4e87568fcc18518e108823c37eabf0514660aa17c"
		logic_hash = "8a2934c28efef6a5fed26dc88d074aee15b0869370c66f6a4d6eaedf070eaa9e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a66134e9344cc5ba403fe0aad70e8a991c61582d6a5640c3b9e4a554374176a2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { 00 10 66 01 00 48 66 01 00 98 07 2B 00 50 66 01 00 95 66 01 }

	condition:
		all of them
}