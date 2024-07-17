
rule ELASTIC_Windows_Vulndriver_Glckio_39C4Abd4 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Glckio (Windows.VulnDriver.GlckIo)"
		author = "Elastic Security"
		id = "39c4abd4-0c14-49e6-ab5c-edc260d28666"
		date = "2022-04-04"
		modified = "2022-08-30"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_GlckIo.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3a5ec83fe670e5e23aef3afa0a7241053f5b6be5e6ca01766d6b5f9177183c25"
		logic_hash = "fd43503c9427a386674c06bb790e110ac23c27d8fc4adedbaa8a9b7cb0cbafd4"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "80971a85f52d52dd80f1887b5b4fc2e101886e60b78b08ca9bb8f781db9f9751"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\GLCKIO2.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and int16 ( uint32(0x3C)+0x18)==0x020b and $str1
}