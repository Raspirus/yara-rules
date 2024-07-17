
rule ELASTIC_Linux_Hacktool_Flooder_Cce8C792 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "cce8c792-ef3e-43c2-b4ad-343de6a69cc7"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L340-L358"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ea56da9584fc36dc67cb1e746bd13c95c4d878f9d594e33221baad7e01571ee6"
		logic_hash = "14700d24e8682ec04f2aae02f5820c4d956db60583b1bc61038b47e709705d0d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "03541eb8a293e88c0b8e6509310f8c57f2cd16b5ff76783a73bde2b614b607fc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 01 48 89 51 08 48 8B 45 A0 8B 55 CC 48 63 D2 48 C1 E2 05 48 }

	condition:
		all of them
}