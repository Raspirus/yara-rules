rule DITEKSHEN_INDICATOR_TOOL_Dwagent_Screencapture : FILE
{
	meta:
		description = "Detect DWAgent Remote Administration Tool Screen Capture Module"
		author = "ditekSHen"
		id = "79586e5e-b7e5-5adc-97f3-0d29ad695079"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_tools.yar#L1555-L1575"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "d3160fd4cce445aa6d2bc6c083893c7610ea5e72824fe9824ad853700f4d3874"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "DWAgentLib" fullword wide
		$s2 = "PYTHONHOME" wide
		$s3 = "VirtualBox" wide
		$s4 = "VMware" wide
		$s5 = "ScreenCapture::prepareCursor#" ascii
		$s6 = "ScreenCapture::getMonitorCount#" ascii
		$s7 = "ScreenCapture::token" ascii
		$s8 = "dwascreencapture" ascii
		$s9 = "inputKeyboard CTRLALTCANC" ascii
		$s10 = "_Z34ScreenCaptureNativeMonitorEnumProc" ascii
		$s11 = "_Z41ScreenCaptureNativeCreateWindowThreadProc" ascii
		$s12 = "_ZN13ScreenCapture" ascii
		$s13 = "isUserInAdminGroup" ascii

	condition:
		uint16(0)==0x5a4d and 7 of them
}