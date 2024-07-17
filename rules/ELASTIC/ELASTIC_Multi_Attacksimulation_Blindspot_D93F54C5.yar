rule ELASTIC_Multi_Attacksimulation_Blindspot_D93F54C5 : FILE MEMORY
{
	meta:
		description = "Detects Multi Attacksimulation Blindspot (Multi.AttackSimulation.Blindspot)"
		author = "Elastic Security"
		id = "d93f54c5-6574-4999-a3c0-39ef688b28dc"
		date = "2022-05-23"
		modified = "2022-08-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Multi_AttackSimulation_Blindspot.yar#L1-L18"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "41984a0ad20ab21186252bb2f3f68604d2cbeea0e1ce22895dd163f7acbf2ca1"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4ec38f841aa4dfe32b1f6b6cd2e361c7298839ef1e983061cb90827135f34a58"
		severity = 1
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "multi"

	strings:
		$a = "\\\\.\\pipe\\blindspot-%d."

	condition:
		all of them
}