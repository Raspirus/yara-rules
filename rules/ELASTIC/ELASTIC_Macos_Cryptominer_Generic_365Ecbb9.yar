rule ELASTIC_Macos_Cryptominer_Generic_365Ecbb9 : FILE MEMORY
{
	meta:
		description = "Detects Macos Cryptominer Generic (MacOS.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "365ecbb9-586e-4962-a5a8-05e871f54eff"
		date = "2021-09-30"
		modified = "2021-10-25"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Cryptominer_Generic.yar#L23-L41"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
		logic_hash = "66f16c8694c5cfde1b5e4eea03c530fa32a15022fa35acdbb676bb696e7deae2"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "5ff82ab60f8d028c9e4d3dd95609f92cfec5f465c721d96947b490691d325484"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$a = { 55 6E 6B 6E 6F 77 6E 20 6E 65 74 77 6F 72 6B 20 73 70 65 63 69 66 69 65 64 20 }

	condition:
		all of them
}