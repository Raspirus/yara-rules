rule ELASTIC_Windows_Trojan_Formbook_5799D1F2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Formbook (Windows.Trojan.Formbook)"
		author = "Elastic Security"
		id = "5799d1f2-4d4f-49d6-b010-67d2fbc04824"
		date = "2022-06-08"
		modified = "2022-09-29"
		reference = "https://www.elastic.co/security-labs/formbook-adopts-cab-less-approach"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Formbook.yar#L48-L67"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "8555a6d313cb17f958fc2e08d6c042aaff9ceda967f8598ac65ab6333d14efd9"
		logic_hash = "8e61eabd11beb9fb35c016983cfb3085f5ceddfc8268522f3b48d20be5b5df6a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "b262c4223e90c539c73831f7f833d25fe938eaecb77ca6d2e93add6f93e7d75d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { E9 C5 9C FF FF C3 E8 00 00 00 00 58 C3 68 }

	condition:
		all of them
}