rule ELASTIC_Windows_Vulndriver_Winio_C9Cc6D00 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Winio (Windows.VulnDriver.WinIo)"
		author = "Elastic Security"
		id = "c9cc6d00-b1ed-4bab-b0f7-4f0d6c03bf08"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_WinIo.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "e1980c6592e6d2d92c1a65acad8f1071b6a404097bb6fcce494f3c8ac31385cf"
		logic_hash = "4b6a78c2c807cf1f569ae9bc275d42d9c895efba7a2d64fec0652e3cb163d553"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "d9050466a2894b63ae86ec8888046efb49053edcc20287b9f17a4e6340a9cf92"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "\\WinioSys.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}