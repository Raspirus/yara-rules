
rule SIGNATURE_BASE_Hiddencobra_R4_Wiper_2 : FILE
{
	meta:
		description = "Detects HiddenCobra Wiper"
		author = "NCCIC Partner"
		id = "75acc3cb-90dd-58e8-b094-ed3f28650b1b"
		date = "2017-12-12"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hiddencobra_wiper.yar#L22-L35"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f537f67be28f854db0d56199d2a43f90cf6c80469a6f9853db0cd550440c7e1f"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$PhysicalDriveSTR = "\\\\.\\PhysicalDrive" wide
		$ExtendedWrite = { B4 43 B0 00 CD 13 }

	condition:
		uint16(0)==0x5a4d and uint16( uint32(0x3c))==0x4550 and all of them
}