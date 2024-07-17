
rule ELASTIC_Windows_Trojan_Dridex_C6F01353 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Dridex (Windows.Trojan.Dridex)"
		author = "Elastic Security"
		id = "c6f01353-cf55-4eac-9f25-6f9cce3b7990"
		date = "2021-08-07"
		modified = "2021-10-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Dridex.yar#L22-L40"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "739682ccb54170e435730c54ba9f7e09f32a3473c07d2d18ae669235dcfe84de"
		logic_hash = "7146204d779610c04badfc7d884ff882ff5f1439b61f889d1edf4419240c5751"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "fbdb230032e3655448d26a679afc612c79d33ac827bcd834e54fe5c05f04d828"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 56 57 55 8B FA 85 C9 74 58 85 FF 74 54 0F B7 37 85 F6 75 04 }

	condition:
		all of them
}