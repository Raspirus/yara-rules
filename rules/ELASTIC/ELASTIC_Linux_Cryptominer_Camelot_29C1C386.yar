
rule ELASTIC_Linux_Cryptominer_Camelot_29C1C386 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Camelot (Linux.Cryptominer.Camelot)"
		author = "Elastic Security"
		id = "29c1c386-c09c-4a58-b454-fc8feb78051d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Camelot.yar#L99-L117"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "fc73bbfb12c64d2f20efa22a6d8d8c5782ef57cb0ca6d844669b262e80db2444"
		logic_hash = "1a3a9065cbb59658c06dfbfc622ccd2e577e988370ffe47848a5859f96db4e24"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2ad8d0d00002c969c50fde6482d797d76d60572db5935990649054b5a103c5d1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 65 20 62 72 61 6E 63 68 00 00 00 49 67 6E 6F 72 69 6E 67 20 }

	condition:
		all of them
}