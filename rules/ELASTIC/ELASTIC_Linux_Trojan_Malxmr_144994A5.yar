
rule ELASTIC_Linux_Trojan_Malxmr_144994A5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Malxmr (Linux.Trojan.Malxmr)"
		author = "Elastic Security"
		id = "144994a5-1e37-4913-b7aa-deed638b1a79"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Malxmr.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
		logic_hash = "4d40337895e63d3dc6f0d94889863f0f5017533658210b902b08d84cf3588cab"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "473e686a74e76bb879b3e34eb207d966171f3e11cf68bde364316c2ae5cd3dc3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 78 71 51 58 5A 5A 4D 31 5A 35 59 6B 4D 78 61 47 4A 58 55 54 4A }

	condition:
		all of them
}