
rule ELASTIC_Windows_Hacktool_Coffloader_81Ba13B8 : FILE MEMORY
{
	meta:
		description = "Detects Windows Hacktool Coffloader (Windows.Hacktool.COFFLoader)"
		author = "Elastic Security"
		id = "81ba13b8-8994-4fe9-98e5-44514c554e8b"
		date = "2024-04-22"
		modified = "2024-05-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_COFFLoader.yar#L1-L43"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c2e03659eb1594dc958e01344cfa9ba126d66736b089db5e3dd1b1c3e3e7d2f7"
		logic_hash = "d4f061af200a0ae9f3276fd6dfcb09ecdf662f29b7c43ea47c69a53d9fe66793"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "ef9f11d9cd6c3b46f7d13ea039dcad6fa24515495466b1102ec8c1c8bed8853e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "BeaconDataParse" ascii fullword
		$a2 = "BeaconDataInt" ascii fullword
		$a3 = "BeaconDataShort" ascii fullword
		$a4 = "BeaconDataLength" ascii fullword
		$a5 = "BeaconDataExtract" ascii fullword
		$a6 = "BeaconFormatAlloc" ascii fullword
		$a7 = "BeaconFormatReset" ascii fullword
		$a8 = "BeaconFormatFree" ascii fullword
		$a9 = "BeaconFormatAppend" ascii fullword
		$a10 = "BeaconFormatPrintf" ascii fullword
		$a11 = "BeaconFormatToString" ascii fullword
		$a12 = "BeaconFormatInt" ascii fullword
		$a13 = "BeaconPrintf" ascii fullword
		$a14 = "BeaconOutput" ascii fullword
		$a15 = "BeaconUseToken" ascii fullword
		$a16 = "BeaconRevertToken" ascii fullword
		$a17 = "BeaconDataParse" ascii fullword
		$a18 = "BeaconIsAdmin" ascii fullword
		$a19 = "BeaconGetSpawnTo" ascii fullword
		$a20 = "BeaconSpawnTemporaryProcess" ascii fullword
		$a21 = "BeaconInjectProcess" ascii fullword
		$a22 = "BeaconInjectTemporaryProcess" ascii fullword
		$a23 = "BeaconCleanupProcess" ascii fullword
		$b1 = "COFFLoader.x64.dll"
		$b2 = "COFFLoader.x86.dll"

	condition:
		5 of ($a*) or 1 of ($b*)
}