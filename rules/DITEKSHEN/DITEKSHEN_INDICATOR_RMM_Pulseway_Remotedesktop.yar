rule DITEKSHEN_INDICATOR_RMM_Pulseway_Remotedesktop : FILE
{
	meta:
		description = "Detects Pulseway Rempte Desktop client"
		author = "ditekSHen"
		id = "8bca3cef-b24f-597a-a6e2-86040ed726f4"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L268-L286"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "a542c11f21ab48f4da69df4e7cb46531658a714687e2c2f8ccf78dc2a0338b68"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.PulseWay"

	strings:
		$s1 = "RemoteControl" ascii
		$s2 = "MM.Monitor.RemoteDesktopClient." ascii
		$s3 = "MM.Monitor.RemoteControl" ascii
		$s4 = "RemoteDesktopClientUpdateInfo" ascii
		$s5 = "ShowRemoteDesktopEnabledSystemsOnly" ascii
		$s6 = "$31f50968-d45c-49d6-ace9-ebc790855a51" ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0xcfd0) and 5 of them
}