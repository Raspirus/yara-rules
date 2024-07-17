
rule ELASTIC_Windows_Generic_Threat_4A605E93 : FILE MEMORY
{
	meta:
		description = "Detects Windows Generic Threat (Windows.Generic.Threat)"
		author = "Elastic Security"
		id = "4a605e93-971d-4257-b382-065159840a4c"
		date = "2024-01-29"
		modified = "2024-02-08"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Generic_Threat.yar#L2232-L2250"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1a84e25505a54e8e308714b53123396df74df1bde223bb306c0dc6220c1f0bbb"
		logic_hash = "6ad7afa5bd03916917e2bbf4d736331f4319b20bfde296d7e62315584813699f"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "58185f9fdf5bbc57cd708d8c963a37824e377a045549f2eb78d5fa501082b687"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = { 20 48 8B 19 45 33 C0 48 85 DB 74 65 4C 89 01 48 83 FA FF 75 17 41 8B C0 44 38 03 74 2D 48 8B CB 48 FF C1 FF C0 44 38 01 75 F6 EB 1E 48 83 FA FE 75 1B 41 8B C0 66 44 39 03 74 0F 48 8B }

	condition:
		all of them
}