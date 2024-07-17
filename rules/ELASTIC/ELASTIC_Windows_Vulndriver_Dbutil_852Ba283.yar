rule ELASTIC_Windows_Vulndriver_Dbutil_852Ba283 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Dbutil (Windows.VulnDriver.DBUtil)"
		author = "Elastic Security"
		id = "852ba283-6a03-44b6-b7e2-b00d1b0586e4"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_DBUtil.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5"
		logic_hash = "78acd081c2517f9c53cb311481c0cc40cc3699b222afc290da1a3698e7bf75b7"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "aec919dfea62a8ed01dde4e8c63fbfa9c2a9720c144668460c00f56171c8db25"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\DBUtilDrv2_64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}