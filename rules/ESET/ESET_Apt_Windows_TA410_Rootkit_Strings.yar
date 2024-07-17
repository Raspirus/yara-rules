import "pe"


rule ESET_Apt_Windows_TA410_Rootkit_Strings : FILE
{
	meta:
		description = "Strings found in TA410's Rootkit"
		author = "ESET Research"
		id = "a6a97721-571e-5414-9b00-5789d7bcd078"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/ta410/ta410.yar#L671-L697"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "1d3ad63508c5e4bca32b9a44b738cb4a7384ccfa5704ce329260adb342ea4e60"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$driver1 = "\\Driver\\kbdclass" wide
		$driver2 = "\\Driver\\mouclass" wide
		$device1 = "\\Device\\KeyboardClass0" wide
		$device2 = "\\Device\\PointerClass0" wide
		$driver3 = "\\Driver\\tcpip" wide
		$device3 = "\\Device\\tcp" wide
		$driver4 = "\\Driver\\nsiproxy" wide
		$device4 = "\\Device\\Nsi" wide
		$reg1 = "\\Registry\\Machine\\SYSTEM\\Setup\\AllowStart\\ceipCommon" wide
		$reg2 = "RHH%d" wide
		$reg3 = "RHP%d" wide
		$s1 = "\\SystemRoot\\System32\\drivers\\hidmouse.sys" wide

	condition:
		uint16(0)==0x5a4d and all of ($s1,$reg*) and ( all of ($driver*) or all of ($device*))
}