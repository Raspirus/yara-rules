rule ELASTIC_Linux_Cryptominer_Zexaf_B90E7683 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Zexaf (Linux.Cryptominer.Zexaf)"
		author = "Elastic Security"
		id = "b90e7683-84bf-4c07-b6ef-54c631280217"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Zexaf.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "98650ebb7e463a06e737bcea4fd2b0f9036fafb0638ba8f002e6fe141b9fecfe"
		logic_hash = "d8485d8fbf00d5c828d7c6c80fef61f228f308e3d27a762514cfb3f00053b30b"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "4ca9fad98bdde19f71c117af9cb87007dc46494666e7664af111beded1100ae4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 F2 C1 E7 18 C1 E2 18 C1 ED 08 09 D5 C1 EE 08 8B 14 24 09 FE }

	condition:
		all of them
}