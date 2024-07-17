rule ELASTIC_Windows_Trojan_Rudebird_3Cbf7Bc6 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Rudebird (Windows.Trojan.RudeBird)"
		author = "Elastic Security"
		id = "3cbf7bc6-71c5-4c7c-a846-7a95c3d28917"
		date = "2023-05-09"
		modified = "2023-06-13"
		reference = "https://www.elastic.co/security-labs/introducing-the-ref5961-intrusion-set"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_RudeBird.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "2095c3b6bde779b5661c7796b5e33bb0c43facf791b272a603b786f889a06a95"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f70bd86d877d9371601c7f65cf50a5bb9b76ba45acbf591bd8e4c1117a0cac1d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 40 53 48 83 EC 20 48 8B D9 B9 D8 00 00 00 E8 FD C1 FF FF 48 8B C8 33 C0 48 85 C9 74 05 E8 3A F2 }

	condition:
		all of them
}