
rule ELASTIC_Linux_Cryptominer_Generic_7Ef74003 : FILE MEMORY
{
	meta:
		description = "Detects Linux Cryptominer Generic (Linux.Cryptominer.Generic)"
		author = "Elastic Security"
		id = "7ef74003-cd1f-4f2f-9c96-4dbcabaa36e4"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Cryptominer_Generic.yar#L621-L639"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "a172cfecdec8ebd365603ae094a16e247846fdbb47ba7fd79564091b7e8942a0"
		logic_hash = "1bde07dbb88357fcc02171512725be94d9fc0427c03afb2d59fbd0658c5d8e2e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "187fd82b91ae6eadc786cadac75de5d919a2b8a592037a5bf8da2efa2539f507"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 41 56 45 31 F6 41 55 49 89 F5 41 54 44 8D 67 01 55 4D 63 E4 53 49 C1 }

	condition:
		all of them
}