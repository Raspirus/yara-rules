rule ELASTIC_Windows_Hacktool_Leigod_3F5C98C4 : FILE
{
	meta:
		description = "Detects Windows Hacktool Leigod (Windows.Hacktool.LeiGod)"
		author = "Elastic Security"
		id = "3f5c98c4-03ba-4919-90b0-604d3cb9361e"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_LeiGod.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0c42fe45ffa9a9c36c87a7f01510a077da6340ffd86bf8509f02c6939da133c5"
		logic_hash = "7570bf1a69df6b493bde41c1de27969e36a3fcb59be574ee2e24e3a61347a146"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "883dcad7097ad5713c4f45ce2fc232c3c1e61cf9dfdc81a194124d5995a64c9e"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\LgDCatcher.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}