
rule ELASTIC_Linux_Trojan_Dropperl_8Bca73F6 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Dropperl (Linux.Trojan.Dropperl)"
		author = "Elastic Security"
		id = "8bca73f6-c3ec-45a3-a5ae-67c871aaf9df"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Dropperl.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e7c17b7916b38494b9a07c249acb99499808959ba67125c29afec194ca4ae36c"
		logic_hash = "2cfad4e436198391185fdae5c4af18ae43841db19da33473fdf18b64b0399613"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "36df2fd9746da80697ef675f84f47efb3cb90e9757677e4f565a7576966eb169"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { E8 95 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 62 00 }

	condition:
		all of them
}