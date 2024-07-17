rule ELASTIC_Windows_Trojan_Cybergate_C219A2F3 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Cybergate (Windows.Trojan.CyberGate)"
		author = "Elastic Security"
		id = "c219a2f3-5ae2-4cdf-97d7-2778954ee826"
		date = "2023-05-04"
		modified = "2023-06-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_CyberGate.yar#L45-L64"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b7204f8caf6ace6ae1aed267de0ad6b39660d0e636d8ee0ecf88135f8a58dc42"
		logic_hash = "8075892728c610c1ceacd0df54615d2a3e833d728d631a9bf81311e8c6485f6e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8a79d1eba89dd08d2e8bdedee834c88dbeabf5f2f249b1e5accdb827671c22c2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 00 00 55 8B EC 83 C4 EC 56 57 8B 45 08 8B F0 8D 7D EC A5 A5 }
		$a2 = { 49 80 39 C3 75 F5 8B C2 C3 55 8B EC 6A 00 6A 00 6A 00 53 56 57 }

	condition:
		all of them
}