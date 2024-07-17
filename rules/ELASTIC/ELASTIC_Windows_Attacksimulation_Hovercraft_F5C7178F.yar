rule ELASTIC_Windows_Attacksimulation_Hovercraft_F5C7178F : FILE MEMORY
{
	meta:
		description = "Detects Windows Attacksimulation Hovercraft (Windows.AttackSimulation.Hovercraft)"
		author = "Elastic Security"
		id = "f5c7178f-9a3f-463d-96a7-0a82cbed9ba2"
		date = "2022-05-23"
		modified = "2022-07-18"
		reference = "046645b2a646c83b4434a893a0876ea9bd51ae05e70d4e72f2ccc648b0f18cb6"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_AttackSimulation_Hovercraft.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		logic_hash = "e707e89904a5fa4d30f94bfc625b736a411df6bb055c0e40df18ae65025a3740"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "8965ab173fd09582c9e77e7c54c9722b91b71ecbe42c4f8a8cc87d9a780ffe8c"
		severity = 1
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "MyHovercraftIsFullOfEels" wide fullword
		$a2 = "WinHttp.dll" fullword

	condition:
		all of them
}