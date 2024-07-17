rule SIGNATURE_BASE_APT_APT29_Sorefang_Disk_Enumeration_Strings : FILE
{
	meta:
		description = "Rule to detect SoreFang based on disk enumeration strings"
		author = "NCSC"
		id = "0ff01793-6fb7-5cff-b4e4-6709269ab0f0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-development"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_grizzly_steppe.yar#L291-L310"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "a4b790ddffb3d2e6691dcacae08fb0bfa1ae56b6c73d70688b097ffa831af064"
		logic_hash = "4a225b767dc922625c333aea866638bc5e239137592e46c17563b9cc380b0eea"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$ = "\x0D\x0AFree on disk: "
		$ = "Total disk: "
		$ = "Error in GetDiskFreeSpaceEx\x0D\x0A"
		$ = "\x0D\x0AVolume label: "
		$ = "Serial number: "
		$ = "File system: "
		$ = "Error in GetVolumeInformation\x0D\x0A"
		$ = "I can not het information about this disk\x0D\x0A"

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and all of them
}