
rule CRAIU_Apt_ZZ_Orangeworm_Kwampirs_Shamoon_Code : FILE
{
	meta:
		description = "Kwampirs and Shamoon common code"
		author = "FBI / cywatch@fbi.gov"
		id = "0d403b3b-a5a8-5ac6-a12d-7181a1ad11b3"
		date = "2020-01-14"
		modified = "2020-03-31"
		reference = "https://assets.documentcloud.org/documents/6821582/FLASH-CP-000118-MW-Downgraded-Version.pdf"
		source_url = "https://github.com/craiu/yararules/blob/68bc7e129467d2c027f06918f28c3196e5c684a1/files/apt_zz_orangeworm.yara#L85-L105"
		license_url = "https://github.com/craiu/yararules/blob/68bc7e129467d2c027f06918f28c3196e5c684a1/LICENSE"
		logic_hash = "5ab949280be87d242ad2843dee001eee5a338e266ef52da55883f7c77e66cf5b"
		score = 75
		quality = 85
		tags = "FILE"
		yara_version = "3.7.0"

	strings:
		$memcpy = { 56 8B F0 85 FF 74 19 85 D2 74 15 8B CF 85 F6 74 0B 2B D7 8A 04 0A 88 01 41 4E 75 F7 8B C7 5E C3 33 C0 5E C3 }
		$strlenW = { 33 C0 85 C9 74 17 80 3C 41 00 75 07 80 7C 41 01 00 74 0A 3D 00 94 35 77 73 03 40 EB E9 C3 }
		$strcmp = { 85 C0 75 07 85 D2 75 40 B0 01 C3 85 D2 74 39 66 83 38 00 56 74 24 0F B7 0A 66 85 C9 74 16
		66 8B 30 83 C2 02 83 C0 02 66 3B F1 75 18 66 83 38 00 75 E4 EB 06 66 83 38 00 75 0A 66 83 3A 00 75 04 B0
		01 5E C3 32 C0 5E C3 32 C0 C3 }

	condition:
		( uint16(0)==0x5a4d) and (1 of them )
}