
rule ELASTIC_Linux_Hacktool_Flooder_7026F674 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "7026f674-83b7-432b-9197-2d71abdb9579"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L41-L59"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "b7a77ebb66664c54d01a57abed5bb034ef2933a9590b595bba0566938b099438"
		logic_hash = "ec8ece1f922260f620fb30d82469f77a4d0239da536fc464fc37a3943cd6e463"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "acf93628ecbda544c6c5d88388ac85bb2755c71544a0980ee1b2854c6bdb7c77"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 08 1E 77 DA 00 43 6F 75 6C 64 20 6E 6F 74 20 6F 70 65 6E 20 }

	condition:
		all of them
}