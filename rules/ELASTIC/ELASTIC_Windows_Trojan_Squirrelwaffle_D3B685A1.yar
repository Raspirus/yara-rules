rule ELASTIC_Windows_Trojan_Squirrelwaffle_D3B685A1 : FILE MEMORY
{
	meta:
		description = "Detects Windows Trojan Squirrelwaffle (Windows.Trojan.Squirrelwaffle)"
		author = "Elastic Security"
		id = "d3b685a1-2d1c-44a3-8d83-ff661d491a52"
		date = "2021-09-21"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Trojan_Squirrelwaffle.yar#L24-L42"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "00d045c89934c776a70318a36655dcdd77e1fedae0d33c98e301723f323f234c"
		logic_hash = "7d187aa75fc767f5009f3090852de4894776f4b3f99f189478e7e9fd9c3acbe7"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "15df7efab9cc40ff57070d18ae67b549c55595d7cbf3ca02963336e4297156c4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 08 85 C0 75 0F 8D 45 94 50 8D 45 D0 6A 20 50 FF D7 83 C4 0C }

	condition:
		all of them
}