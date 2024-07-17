
rule ELASTIC_Macos_Trojan_Bundlore_3965578D : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Bundlore (MacOS.Trojan.Bundlore)"
		author = "Elastic Security"
		id = "3965578d-3180-48e4-b5be-532e880b1df9"
		date = "2021-10-05"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_Bundlore.yar#L81-L99"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "d72543505e36db40e0ccbf14f4ce3853b1022a8aeadd96d173d84e068b4f68fa"
		logic_hash = "6bd24640e0a3aa152fcd90b6975ee4fb7e99ab5f2d48d3a861bc804c526c90b6"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e41f08618db822ba5185e5dc3f932a72e1070fbb424ff2c097cab5e58ad9e2db"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 35 33 2A 00 00 60 80 35 2D 2A 00 00 D0 80 35 27 2A 00 00 54 80 35 21 2A 00 00 }

	condition:
		all of them
}