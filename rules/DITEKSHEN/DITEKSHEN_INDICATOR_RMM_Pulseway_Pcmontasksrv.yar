import "pe"


rule DITEKSHEN_INDICATOR_RMM_Pulseway_Pcmontasksrv : FILE
{
	meta:
		description = "Detects Pulseway pcmontask and service user agent responsible for Remote Control, Screens View, Computer Lock, etc"
		author = "ditekSHen"
		id = "83901679-ffff-5710-b472-ece592e6764f"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L245-L266"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "80ba217960dd1ddeb220545c1cccbe96d9b676d327364e1ca8a9dde2b059261f"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.PulseWay"

	strings:
		$s1 = "MM.Monitor." ascii
		$s2 = "RDAgentSessionSettingsV" ascii
		$s3 = "CheckForMacOSRemoteDesktopUpdateCompletedEvent" ascii
		$s4 = "ConfirmAgentStarted" ascii
		$s5 = "GetScreenshot" ascii
		$s6 = "UnloadRemoteDesktopDlls" ascii
		$s7 = "CtrlAltDeleteProc" ascii
		$s8 = "$7cfc3b88-6dc4-49fc-9f0a-bf9e9113a14d" ascii
		$s9 = "computermonitor.mmsoft.ro" ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0xcfd0) and 7 of them
}