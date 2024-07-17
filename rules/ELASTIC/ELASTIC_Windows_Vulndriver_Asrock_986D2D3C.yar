rule ELASTIC_Windows_Vulndriver_Asrock_986D2D3C : FILE
{
	meta:
		description = "Detects Windows Vulndriver Asrock (Windows.VulnDriver.Asrock)"
		author = "Elastic Security"
		id = "986d2d3c-96d1-4c74-a594-51c6df3b2896"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_Asrock.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3943a796cc7c5352aa57ccf544295bfd6fb69aae147bc8235a00202dc6ed6838"
		logic_hash = "d767a1ecdff557753f80ac9d73f02364dd035f7a287d0f260316f807364af2d5"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "17a021c4130a41ca6714f2dd7f33c100ba61d6d2d4098a858f917ab49894b05b"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\AsrDrv106.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}