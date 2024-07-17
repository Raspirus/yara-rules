
rule ELASTIC_Windows_Trojan_Clipbanker_F9F9E79D : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Clipbanker (Windows.Trojan.Clipbanker)"
		author = "Elastic Security"
		id = "f9f9e79d-ce71-4b6c-83e0-ac6e06252c25"
		date = "2022-04-23"
		modified = "2022-06-09"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Clipbanker.yar#L45-L63"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0407e8f54490b2a24e1834d99ec0452f217499f1e5a64de3d28439d71d16d43c"
		logic_hash = "a71d75719133e8b84956ec002cb31f82386ef711fa2af79d204d176492cd354b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ec985e1273d8ff52ea7f86271a96db01633402facf8d140d11b82e5539e4b5fd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 7E 7E 0F B7 04 77 83 F8 41 74 69 83 F8 42 74 64 83 F8 43 74 5F 83 }

	condition:
		all of them
}