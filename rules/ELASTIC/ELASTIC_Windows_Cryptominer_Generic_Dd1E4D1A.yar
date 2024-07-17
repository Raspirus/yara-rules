
rule ELASTIC_Windows_Cryptominer_Generic_Dd1E4D1A : FILE
{
	meta:
		description = "Detects Windows Cryptominer Generic (Windows.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "dd1e4d1a-2e2f-4af0-bd66-2e12367dd064"
		date = "2021-01-12"
		modified = "2021-08-23"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Cryptominer_Generic.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "7ac1d7b6107307fb2442522604c8fa56010d931392d606ac74dcea6b7125954b"
		logic_hash = "b7289c4688ec67d59e67755461f1f4e0c3f47ef9f8c73fc1dcc1d168baf11623"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "a00e3e08e11d10a7a4bf1110a5110e4d0a4d2acf0974aca9dfc1ad5f21c80df7"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a = { EF F9 66 0F EF FA 66 0F FE FE 66 0F 6F B0 B0 00 00 00 66 0F }

	condition:
		all of them
}