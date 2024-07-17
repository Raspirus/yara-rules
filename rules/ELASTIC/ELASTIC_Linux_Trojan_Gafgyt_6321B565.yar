
rule ELASTIC_Linux_Trojan_Gafgyt_6321B565 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Gafgyt (Linux.Trojan.Gafgyt)"
		author = "Elastic Security"
		id = "6321b565-ed25-4bf2-be4f-3ffa0e643085"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Gafgyt.yar#L80-L98"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "cd48addd392e7912ab15a5464c710055f696990fab564f29f13121e7a5e93730"
		logic_hash = "ad5c73ab68059101acf2fd8cfb3d676fd1ff58811e1c4b9008c291361ee951b8"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "c1d286e82426cbf19fc52836ef9a6b88c1f6e144967f43760df93cf1ab497d07"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { D8 89 D0 01 C0 01 D0 C1 E0 03 8B 04 08 83 E0 1F 0F AB 84 9D 58 FF }

	condition:
		all of them
}