
rule ELASTIC_Multi_Trojan_Sliver_3Bde542D : FILE MEMORY
{
	meta:
		description = "Detects Multi Trojan Sliver (Multi.Trojan.Sliver)"
		author = "Elastic Security"
		id = "3bde542d-df52-4f05-84ff-de67e90592a9"
		date = "2022-08-31"
		modified = "2022-09-29"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Multi_Trojan_Sliver.yar#L27-L50"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "05461e1c2a2e581a7c30e14d04bd3d09670e281f9f7c60f4169e9614d22ce1b3"
		logic_hash = "23a0e28c1423f577a147efdf927f2dc71871760e38d4d7494ead2920b90ef05e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "e52e39644274e3077769da4d04488963c85a0b691dc9973ad12d51eb34ba388b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$a1 = "B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb" ascii fullword
		$b1 = "InvokeSpawnDllReq" ascii fullword
		$b2 = "NetstatReq" ascii fullword
		$b3 = "HTTPSessionInit" ascii fullword
		$b4 = "ScreenshotReq" ascii fullword
		$b5 = "RegistryReadReq" ascii fullword

	condition:
		1 of ($a*) or all of ($b*)
}