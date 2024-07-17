rule ELASTIC_Macos_Cryptominer_Generic_4E7D4488 : FILE MEMORY
{
	meta:
		description = "Detects Macos Cryptominer Generic (MacOS.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "4e7d4488-2e0c-4c74-84f9-00da103e162a"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Cryptominer_Generic.yar#L43-L61"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
		logic_hash = "708b21b687c8b853a9b5f8a50d31119e4f0a02a5b63f81ba1cac8c06acd19214"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "4e7f22e8084734aeded9b1202c30e6a170a6a38f2e486098b4027e239ffed2f6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 69 73 20 66 69 65 6C 64 20 74 6F 20 73 68 6F 77 20 6E 75 6D 62 65 72 20 6F 66 }

	condition:
		all of them
}