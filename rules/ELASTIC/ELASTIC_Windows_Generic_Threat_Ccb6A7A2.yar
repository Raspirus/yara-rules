rule ELASTIC_Windows_Generic_Threat_Ccb6A7A2 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "ccb6a7a2-6003-4ba0-aefc-3605d085486d"
		date = "2024-01-17"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L1667-L1686"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "60503212db3f27a4d68bbfc94048ffede04ad37c78a19c4fe428b50f27af7a0d"
		logic_hash = "312265bbc4330a463bbe7478c70233f5df3353bda3c450562f2414f3675ba91e"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "a73b0e067fce2e87c08359b4bb2ba947cc276ff0a07ff9e04cabde529e264192"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 40 52 61 6E 67 65 3A 62 79 74 65 73 3D 30 2D }
		$a2 = { 46 49 77 41 36 4B 58 49 75 4E 66 4B 71 49 70 4B 30 4D 57 4D 74 49 38 4B 67 4D 68 49 39 4B 30 4D 53 49 6A 4B 66 4D 73 49 76 4B 75 4D 64 49 70 4B 30 4D 73 49 66 4B 68 4D 6F 49 69 43 6F 4D 6C 49 71 4B }

	condition:
		all of them
}