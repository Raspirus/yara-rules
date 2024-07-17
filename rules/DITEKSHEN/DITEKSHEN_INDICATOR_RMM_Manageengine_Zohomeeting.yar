import "pe"


rule DITEKSHEN_INDICATOR_RMM_Manageengine_Zohomeeting : FILE
{
	meta:
		description = "Detects ManageEngine Zoho Meeting (dc_rds.exe)"
		author = "ditekSHen"
		id = "b15efdd1-323c-5ed6-894d-b44f04d2eaf3"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L304-L324"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "8066bcd17245efcc73f2bef7f022ad23ab648fe0ad15ca66c0d387ce4eda998b"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.ManageEngine-ZohoMeeting"

	strings:
		$s1 = "bin\\ClientAuthHandler.dll" wide
		$s2 = "AgentHook.dll" wide
		$s3 = "UEMS - Remote Control" wide
		$s4 = "Install hook...." wide
		$s5 = "india.adventnet.com/meet.sas?k=" ascii
		$s6 = "dcTcpSocket::" ascii
		$s7 = "%s/%s?clientId=%s&sessionId=%s&clientName=%s&ticket=%s&connectionId=%s" ascii
		$s8 = ".\\engines\\ccgost\\gost_" ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}