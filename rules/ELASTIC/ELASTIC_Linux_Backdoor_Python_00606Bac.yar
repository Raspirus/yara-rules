rule ELASTIC_Linux_Backdoor_Python_00606Bac : FILE MEMORY
{
	meta:
		description = "Detects Linux Backdoor Python (Linux.Backdoor.Python)"
		author = "Elastic Security"
		id = "00606bac-83eb-4a58-82d2-e4fd16d30846"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Backdoor_Python.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b3e3728d43535f47a1c15b915c2d29835d9769a9dc69eb1b16e40d5ba1b98460"
		logic_hash = "92ad2cf4aa848c8f3bcedd319654bf5ef873cd4daba62572381c7e20f0296b82"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cce1d0e7395a74c04f15ff95f6de7fd7d5f46ede83322b832df74133912c0b17"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { F4 01 83 45 F8 01 8B 45 F8 0F B6 00 84 C0 75 F2 83 45 F8 01 8B }

	condition:
		all of them
}