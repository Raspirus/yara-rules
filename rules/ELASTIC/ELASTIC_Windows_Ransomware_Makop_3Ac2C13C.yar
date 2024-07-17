
rule ELASTIC_Windows_Ransomware_Makop_3Ac2C13C : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Makop (Windows.Ransomware.Makop)"
		author = "Elastic Security"
		id = "3ac2c13c-45f0-4108-81fb-e57c3cc0e622"
		date = "2021-08-05"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Makop.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "854226fc4f5388d40cd9e7312797dd63739444d69a67e4126ef60817fa6972ad"
		logic_hash = "3fa7c506010a87ac97f415db32c21af091dff26fd912a8f9f5bb5e8d43a8da9e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4658a5b34ecb2a7432b7ab48041cc064d917b88a4673f21aa6c3c44b115c9b8c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 20 00 75 15 8B 44 24 10 8B 4C 24 08 8B 54 24 0C 89 46 20 89 }

	condition:
		all of them
}