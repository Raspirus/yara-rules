
rule ELASTIC_Windows_Generic_Threat_278C589E : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "278c589e-fca0-4228-8ffa-6b5e4627b1b1"
		date = "2024-01-31"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2437-L2455"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cccc6c1bf15a7d5725981de950475e272c277bc3b9d266c5debf0fc698770355"
		logic_hash = "59bbbecd73541750f7221b12895ccf51e1a6863ceca62e23f541df904ad23587"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "573b6c5400400b167edd94e12332d421a32dc52138a2a933f2fa85f8409c8e4a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 49 6E 73 74 61 6C 6C 65 72 20 77 69 6C 6C 20 6E 6F 77 20 64 6F 77 6E 6C 6F 61 64 20 66 69 6C 65 73 20 72 65 71 75 69 72 65 64 20 66 6F 72 20 69 6E 73 74 61 6C 6C 61 74 69 6F 6E 2E }

	condition:
		all of them
}