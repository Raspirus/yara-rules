
rule ELASTIC_Linux_Hacktool_Flooder_C680C9Fd : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Flooder (Linux.Hacktool.Flooder)"
		author = "Elastic Security"
		id = "c680c9fd-34ad-4d92-b8d6-1b511c7c07a3"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Flooder.yar#L460-L478"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "ea56da9584fc36dc67cb1e746bd13c95c4d878f9d594e33221baad7e01571ee6"
		logic_hash = "a283132ffdd109b8b1f01e5a3e2700b70b742945c7ae8b15b2b244fb249a5e3d"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "5cb5b36d3ae5525b992a9d395b54429f52b11ea229e0cecbd62317af7b5faf84"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 45 A0 8B 55 CC 48 63 D2 48 C1 E2 05 48 01 D0 48 8D 48 10 48 8B }

	condition:
		all of them
}