
rule ELASTIC_Linux_Generic_Threat_98Bbca63 : FILE MEMORY
{
	meta:
		description = "Detects Linux Generic Threat (Linux.Generic.Threat)"
		author = "Elastic Security"
		id = "98bbca63-68c4-4b32-8cb6-50f9dad0a8f2"
		date = "2024-01-22"
		modified = "2024-02-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Generic_Threat.yar#L328-L347"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1d4d3d8e089dcca348bb4a5115ee2991575c70584dce674da13b738dd0d6ff98"
		logic_hash = "1728d47b3f364cff02ae61ccf381ecab0c1fe46a5c76d832731fdf7acc1caf55"
		score = 75
		quality = 71
		tags = "FILE, MEMORY"
		fingerprint = "d10317a1a09e86b55eb7b00a87cb010e0d2f11ade2dccc896aaeba9819bd6ca5"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = { 64 65 73 63 72 69 70 74 69 6F 6E 3D 4C 4B 4D 20 72 6F 6F 74 6B 69 74 }
		$a2 = { 61 75 74 68 6F 72 3D 6D 30 6E 61 64 }

	condition:
		all of them
}