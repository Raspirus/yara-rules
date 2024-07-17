rule ELASTIC_Windows_Ransomware_Darkside_D7Fc4594 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Darkside (Windows.Ransomware.Darkside)"
		author = "Elastic Security"
		id = "d7fc4594-185c-4afb-986e-5718c0beabf1"
		date = "2021-05-20"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Darkside.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bfb31c96f9e6285f5bb60433f2e45898b8a7183a2591157dc1d766be16c29893"
		logic_hash = "0083fb64955973e7dbbb35d08cb780fa0b4ff4d064c102dc8f86e29af8358bad"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "90444cd2d3a38296b4979f91345a9999b0032f6c0abee6ff7c15d149b59e5e88"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 5F 30 55 56 BD 0A 00 00 00 8B 07 8B 5F 10 8B 4F 20 8B 57 30 }

	condition:
		any of them
}