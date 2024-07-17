rule ELASTIC_Linux_Hacktool_Flooder_1Bf0E994 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "1bf0e994-2648-4dbb-9b9c-b86b9a347700"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L120-L138"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "1ea2dc13eec0d7a8ec20307f5afac8e9344d827a6037bb96a54ad7b12f65b59c"
		logic_hash = "2c1099b8078ac306f7cb67be5b5b5e34f57414b9aa26bdd6c26d3636c80846cd"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1f844c349b47dd49a75d50e43b6664e9d2b95c362efb730448934788b6bddb79"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 05 88 10 48 8B 45 B8 0F B6 10 83 E2 0F 83 CA 40 88 10 48 8B }

	condition:
		all of them
}