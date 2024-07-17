
rule ELASTIC_Linux_Hacktool_Flooder_D90C4Cbe : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "d90c4cbe-4d0a-4341-a58b-a472b67282d6"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L440-L458"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
		logic_hash = "145d32f8a06af18e6f13b0905cc51fd7b1a9e00b41b0f0a5d537ada2b54a94b5"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "64796aa7faa2e945b5c856c1c913cb62175413dc1df88505dececcfbd2878cb1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 D8 F7 D0 5B 5D C3 55 48 89 E5 48 83 EC 40 48 89 7D C8 48 89 }

	condition:
		all of them
}