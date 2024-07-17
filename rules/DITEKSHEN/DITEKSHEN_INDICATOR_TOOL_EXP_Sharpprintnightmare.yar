import "pe"


rule DITEKSHEN_INDICATOR_TOOL_EXP_Sharpprintnightmare : FILE
{
	meta:
		description = "Detect SharpPrintNightmare"
		author = "ditekSHen"
		id = "15f52fce-27cc-52e7-91d5-7e2f6db5b596"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L941-L961"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "22c890a22ce6b7c1a06068018364f7c5a2afe1bee5b5bc6a8bae3703a11fac26"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "RevertToSelf() Error:" wide
		$s2 = "NeverGonnaGiveYou" wide
		$s3 = "\\Amd64\\UNIDRV.DLL" wide
		$s4 = ":\\Windows\\System32\\DriverStore\\FileRepository\\" wide
		$s5 = "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\old\\{0}\\{1}" wide
		$s6 = "\\SharpPrintNightmare\\" ascii
		$s7 = { 4e 61 6d 65 09 46 75 6c 6c 54 72 75 73 74 01 }
		$s8 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\PackageInstallation\\Windows x64\\DriverPackages" wide
		$s9 = "ntprint.inf_amd64" wide
		$s10 = "AddPrinterDriverEx" wide
		$s11 = "addPrinter" ascii
		$s12 = "DRIVER_INFO_2" ascii
		$s13 = "APD_COPY_" ascii

	condition:
		uint16(0)==0x5a4d and 7 of them
}