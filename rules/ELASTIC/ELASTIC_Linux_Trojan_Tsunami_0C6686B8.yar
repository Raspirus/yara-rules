rule ELASTIC_Linux_Trojan_Tsunami_0C6686B8 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "0c6686b8-8880-4a2c-ba70-9a9840a618b0"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L121-L139"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
		logic_hash = "731bb3f9957e8777040c0b7b316a818f4ee1ca9a113fb9eed24ee61bfc71e11d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "7bab1c0cf4fb79c50369f991373178ef3b5d3f7afd765dac06e86ac0c27e0c83"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 F8 31 C0 48 8B 45 C8 0F B7 40 02 66 89 45 D0 48 8B 45 C8 8B }

	condition:
		all of them
}