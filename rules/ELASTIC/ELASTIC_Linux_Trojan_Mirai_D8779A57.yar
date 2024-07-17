
rule ELASTIC_Linux_Trojan_Mirai_D8779A57 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Mirai (Linux.Trojan.Mirai)"
		author = "Elastic Security"
		id = "d8779a57-c6ee-4627-9eb0-ab9305bd2454"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Mirai.yar#L577-L595"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "c490586fbf90d360cf3b2f9e2dc943809441df3dfd64dadad27fc9f5ee96ec74"
		logic_hash = "2154786bbb6dbcc280aaa9e2b75106b585d04c7c85f6162f441c81dc54663cb3"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "6c7a18cc03cacef5186d4c1f6ce05203cf8914c09798e345b41ce0dcee1ca9a6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { B6 FF 41 89 D0 85 FF 74 29 38 56 08 74 28 48 83 C6 10 31 D2 }

	condition:
		all of them
}