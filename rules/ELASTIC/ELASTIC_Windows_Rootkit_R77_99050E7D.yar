
rule ELASTIC_Windows_Rootkit_R77_99050E7D : FILE MEMORY
{
	meta:
		description = "Detects Windows Rootkit R77 (Windows.Rootkit.R77)"
		author = "Elastic Security"
		id = "99050e7d-b9b2-411f-b315-0ac7f556314c"
		date = "2023-05-09"
		modified = "2023-06-13"
		reference = "https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Rootkit_R77.yar#L44-L64"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3dc94c88caa3169e096715eb6c2e6de1b011120117c0a51d12f572b4ba999ea6"
		logic_hash = "0fedf4698cc652076090b1fe256d05d2c0bc3ad2ab7ed5faa270c5c7fe0efca1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1fa724556616eed4adfe022602795ffc61fe64dd910b5b83fd7610933b79d71f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 5C 00 24 00 37 00 37 00 63 00 68 00 69 00 6C 00 64 00 70 00 72 00 6F 00 63 00 36 00 34 00 }
		$a2 = { 5C 00 5C 00 2E 00 5C 00 70 00 69 00 70 00 65 00 5C 00 24 00 37 00 37 00 63 00 68 00 69 00 6C 00 64 00 70 00 72 00 6F 00 63 00 33 00 32 00 }

	condition:
		all of them
}