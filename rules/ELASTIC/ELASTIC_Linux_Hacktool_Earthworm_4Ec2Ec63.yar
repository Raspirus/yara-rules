rule ELASTIC_Linux_Hacktool_Earthworm_4Ec2Ec63 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Earthworm (Linux.Hacktool.Earthworm)"
		author = "Elastic Security"
		id = "4ec2ec63-6b22-404f-a217-4e7d32bfbe9f"
		date = "2021-01-12"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Earthworm.yar#L61-L79"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "dc412d4f2b0e9ca92063a47adfb0657507d3f2a54a415619db5a7ccb59afb204"
		logic_hash = "25f616c5440a48aef0f824cb6859e88787db4f42c1ec904a3d3bd72f3a64116e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "1dfb594e369ca92a9e3f193499708c4992f6497ff1aa74ae0d6c2475a7e87641"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 E5 48 83 EC 20 BA 04 00 00 00 48 8D 45 F0 48 89 7D F8 89 }

	condition:
		all of them
}