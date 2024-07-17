rule ELASTIC_Windows_Vulndriver_ATSZIO_E22Cc429 : FILE
{
	meta:
		description = "Name: ATSZIO.sys"
		author = "Elastic Security"
		id = "e22cc429-0285-4ab1-ae35-7e905e467182"
		date = "2022-04-07"
		modified = "2022-04-07"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_ATSZIO.yar#L1-L20"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "01e024cb14b34b6d525c642a710bfa14497ea20fd287c39ba404b10a8b143ece"
		logic_hash = "e3f057d5a5c47a1f3b4d50e2ad0ebb3a4ffe0efe513a0d375f827fadb3328d80"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "21cf1d00acde85bdae8c4cf6d59b0d224458de30a32dbddebd99eab48e1126bb"
		threat_name = "Windows.VulnDriver.ATSZIO"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 54 00 53 00 5A 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $original_file_name
}