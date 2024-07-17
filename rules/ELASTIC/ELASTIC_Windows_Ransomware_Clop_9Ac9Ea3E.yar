rule ELASTIC_Windows_Ransomware_Clop_9Ac9Ea3E : BETA FILE MEMORY
{
	meta:
		description = "Identifies CLOP ransomware in unpacked state"
		author = "Elastic Security"
		id = "9ac9ea3e-72e1-4151-a2f8-87869f5f98e3"
		date = "2020-05-03"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Clop.yar#L52-L71"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "1228ee4b934faf1d5f8cf4518974cd2c80a73d84c8a354bde4813fb97ba516d7"
		score = 75
		quality = 75
		tags = "BETA, FILE, MEMORY"
		fingerprint = "1cb0adb36e94ef8f8d74862250205436ed3694ed7719d8e639cfdd0c8632fd6c"
		threat_name = "Windows.Ransomware.Clop"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$c1 = { 8B 1D D8 E0 40 00 33 F6 8B 3D BC E0 40 00 }

	condition:
		1 of ($c*)
}