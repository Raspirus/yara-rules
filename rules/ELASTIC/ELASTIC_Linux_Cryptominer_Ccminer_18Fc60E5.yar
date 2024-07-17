rule ELASTIC_Linux_Cryptominer_Ccminer_18Fc60E5 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Ccminer (Linux.Cryptominer.Ccminer)"
		author = "Elastic Security"
		id = "18fc60e5-680c-4ff6-8a76-12cc3ae9cd3d"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Ccminer.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "dbb403a00c75ef2a74b41b8b58d08a6749f37f922de6cc19127a8f244d901c60"
		logic_hash = "75db45ccbeb558409ee9398065591472d4aee0382be5980adb9d0fb41e557789"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "461e942fcaf5faba60c3dc39d8089f9d506ff2daacb2a22573fb35bcfee9b6f1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 00 68 27 52 22 02 02 32 22 22 03 5C 8B AE 00 00 00 48 03 5C }

	condition:
		all of them
}