
rule ELASTIC_Windows_Ransomware_Whispergate_C80F3B4B : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Whispergate (Windows.Ransomware.WhisperGate)"
		author = "Elastic Security"
		id = "c80f3b4b-f91b-4b8d-908e-f64c2c5d4b30"
		date = "2022-01-17"
		modified = "2022-01-17"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_WhisperGate.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"
		logic_hash = "04452141a867d4f6fce618c21795cc142a1265b56c62ecb9e579003d36b4b2b9"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e8ad6a7cfabf96387deee56f38b0f0ba6d8fe85e7be9f153ccf72d69ee5db1c9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$buffer = { E8 ?? ?? ?? ?? BE 20 40 40 00 29 C4 8D BD E8 DF FF FF E8 ?? ?? ?? ?? B9 00 08 00 00 F3 A5 }
		$note = { 59 6F 75 72 20 68 61 72 64 20 64 72 69 76 65 20 68 61 73 20 62 65 65 6E 20 63 6F 72 72 75 70 74 65 64 2E 0D 0A }

	condition:
		all of them
}