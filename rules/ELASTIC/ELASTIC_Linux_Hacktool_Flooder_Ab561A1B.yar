
rule ELASTIC_Linux_Hacktool_Flooder_Ab561A1B : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "ab561a1b-d8dd-4768-9b4c-07ef4777b252"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L380-L398"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1b7df0d491974bead05d04ede6cf763ecac30ecff4d27bb4097c90cc9c3f4155"
		logic_hash = "5720d2ada4b33514f2d528417876606d2951786df8b0512f9e8833b8ec87127a"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "081dd5eb061c8023756e413420241e20a2c86097f95859181ca5d6b1d24fdd76"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { B5 50 FF FF FF 64 48 8B 04 25 28 00 00 00 48 89 45 C8 31 C0 83 BD 5C FF FF }

	condition:
		all of them
}