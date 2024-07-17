rule ELASTIC_Windows_Trojan_Darkgate_Fa1F1338 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Darkgate (Windows.Trojan.DarkGate)"
		author = "Elastic Security"
		id = "fa1f1338-c920-4db9-a7ec-cd11d7e1558b"
		date = "2023-12-14"
		modified = "2024-01-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_DarkGate.yar#L1-L21"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1fce9ee9254dd0641387cc3b6ea5f6a60f4753132c20ca03ce4eed2aa1042876"
		logic_hash = "d5447a57fc57af52c263b84522346a3e94a464a698de8be77eab3b56156164f2"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "182481e23eb10f0a8b7d0d536e2d8d36ab5e51fd798caebff4d38d55b5549244"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str0 = "DarkGate has recovered from a Critical error"
		$str1 = "Executing DarkGate inside the new desktop..."
		$str2 = "Restart Darkgate "

	condition:
		2 of them
}