rule ELASTIC_Windows_Trojan_Fickerstealer_F2159Bec : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Fickerstealer (Windows.Trojan.Fickerstealer)"
		author = "Elastic Security"
		id = "f2159bec-a3ce-47a9-91ad-43b8a19ac172"
		date = "2021-07-22"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Fickerstealer.yar#L22-L40"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a4113ccb55e06e783b6cb213647614f039aa7dbb454baa338459ccf37897ebd6"
		logic_hash = "d36cb90b526a291858291d615272baa78881309c83376f4d4cce1768c740ddbc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "0671691c6d5c7177fe155e4076ab39bf5f909ed300f32c1530e80d471dff0296"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 10 12 F2 0F 10 5A 08 31 C1 89 C6 8B 42 50 89 7D F0 F2 0F 11 8D 18 FF }

	condition:
		all of them
}