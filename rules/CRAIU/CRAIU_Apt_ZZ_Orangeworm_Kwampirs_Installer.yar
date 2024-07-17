rule CRAIU_Apt_ZZ_Orangeworm_Kwampirs_Installer : FILE
{
	meta:
		description = "Kwampirs installer xor keys and Unicode string length routine"
		author = "FBI / cywatch@fbi.gov"
		id = "8c80d0d5-8c65-5cef-ad86-b38f4d671bec"
		date = "2020-01-14"
		modified = "2020-03-31"
		reference = "https://assets.documentcloud.org/documents/6821582/FLASH-CP-000118-MW-Downgraded-Version.pdf"
		source_url = "https://github.com/craiu/yararules/blob/68bc7e129467d2c027f06918f28c3196e5c684a1/files/apt_zz_orangeworm.yara#L109-L127"
		license_url = "https://github.com/craiu/yararules/blob/68bc7e129467d2c027f06918f28c3196e5c684a1/LICENSE"
		logic_hash = "ac9c3ba7188cbbe736ff81b41086fdc874ac24ae83d3cec390907f8edd0a0ce5"
		score = 75
		quality = 85
		tags = "FILE"
		yara_version = "3.7.0"

	strings:
		$string_key = { 6C 35 E3 31 1B 23 F9 C9 65 EB F3 07 93 33 F2 A3 }
		$resource_key = { 28 99 B6 17 63 33 EE 22 97 97 55 B5 7A C4 E1 A4 }
		$strlenW = { 33 C0 85 C9 74 17 80 3C 41 00 75 07 80 7C 41 01 00 74 0A 3D 00 94 35 77 73 03 40 EB E9 C3}

	condition:
		(( uint16(0)==0x5a4d) and (2 of them ))
}