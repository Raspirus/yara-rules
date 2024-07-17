rule ELASTIC_Windows_Generic_Threat_Bbf2A354 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "bbf2a354-64e5-4115-aaf7-2705194445da"
		date = "2024-01-22"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1971-L1989"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b4e6c748ad88070e39b53a9373946e9e404623326f710814bed439e5ea61fc3e"
		logic_hash = "6be2fae41199daea6b9d0394c9af7713543333a50620ef417bb8439d5a07f336"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "8fb9fcf8b9c661e4966b37a107d493e620719660295b200cfc67fc5533489dee"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 54 68 61 74 20 70 72 6F 67 72 61 6D 20 6D 75 73 74 20 62 65 20 72 75 6E 20 75 6E 64 65 72 20 57 69 6E 33 32 }

	condition:
		all of them
}