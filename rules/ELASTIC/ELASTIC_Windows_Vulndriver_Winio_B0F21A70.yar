rule ELASTIC_Windows_Vulndriver_Winio_B0F21A70 : FILE
{
	meta:
		description = "Detects Windows Vulndriver Winio (Windows.VulnDriver.WinIo)"
		author = "Elastic Security"
		id = "b0f21a70-b563-4b18-8ef9-73885125e88b"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_VulnDriver_WinIo.yar#L21-L39"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374"
		logic_hash = "c82d95e805898f9a9a1ffccb483e506df0a53dc420068314e7c724e4947f3572"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "00d8142a30e9815f8e4c53443221fc1c3882c8b6f68e77a8ed7ffe4fc8852488"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "IOCTL_WINIO_WRITEMSR"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}