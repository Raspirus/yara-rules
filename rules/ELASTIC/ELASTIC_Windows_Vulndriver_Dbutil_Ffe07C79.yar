
rule ELASTIC_Windows_Vulndriver_Dbutil_Ffe07C79 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Dbutil (Windows.VulnDriver.DBUtil)"
		author = "Elastic Security"
		id = "ffe07c79-d97b-43ba-92b9-206bb4c7bdd4"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_DBUtil.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "87e38e7aeaaaa96efe1a74f59fca8371de93544b7af22862eb0e574cec49c7c3"
		logic_hash = "18b1c93c395b105f446b4c968441e0a43e42b1bd7efcf6501a89eb92cbd21824"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "16c22aba1e8c677cc22d3925dd7416a3c55c67271940289936a2cdc199a53798"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\DBUtilDrv2_32.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}