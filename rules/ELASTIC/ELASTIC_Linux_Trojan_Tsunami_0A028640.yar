
rule ELASTIC_Linux_Trojan_Tsunami_0A028640 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Tsunami (Linux.Trojan.Tsunami)"
		author = "Elastic Security"
		id = "0a028640-581f-4183-9313-e36c5812e217"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Tsunami.yar#L241-L259"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e36081f0dbd6d523c9378cdd312e117642b0359b545b29a61d8f9027d8c0f2f0"
		logic_hash = "663f110c7214498466759b66a83ff1844f5bf45ce706fa8ad0e8b205cc9c8f72"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1b296e8baffbe3e0e49aee23632afbfab75147f31561d73eb0c82f909c5ec718"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 10 85 C0 74 2D 8B 45 0C 0F B6 00 84 C0 74 19 8B 45 0C 83 C0 01 83 }

	condition:
		all of them
}