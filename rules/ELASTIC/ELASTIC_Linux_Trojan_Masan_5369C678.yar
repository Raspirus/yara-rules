rule ELASTIC_Linux_Trojan_Masan_5369C678 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Masan (Linux.Trojan.Masan)"
		author = "Elastic Security"
		id = "5369c678-9a74-42fe-a4b3-b4d48126bb22"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Masan.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f2de9f39ca3910d5b383c245d8ca3c1bdf98e2309553599e0283062e0aeff17f"
		logic_hash = "e57b105004216a6054b0561b69cce00c35255c5bd33aa8e403d0a3967cd0697e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5fd243bf05cafd7db33d6c0167f77148ae53983906e917e174978130ae08062a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 C0 89 45 E4 83 7D E4 FF 75 ?? 68 ?? 90 04 08 }

	condition:
		all of them
}