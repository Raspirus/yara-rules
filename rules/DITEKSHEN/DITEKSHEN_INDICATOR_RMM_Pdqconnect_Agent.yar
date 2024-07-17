import "pe"


rule DITEKSHEN_INDICATOR_RMM_Pdqconnect_Agent : FILE
{
	meta:
		description = "Detects PDQ Connect Agent. Review RMM Inventory"
		author = "ditekSHen"
		id = "067e75a3-291b-500f-865d-8758eebe91e7"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L200-L227"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "34d0b07925551d1b08b86aa226c59aba569b6548cfa00a86ce6b1f271e427662"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$api1 = "/devices/register" ascii
		$api2 = "/devices/socket/websocket?device_id=" ascii
		$api3 = "/devices/tasks" ascii
		$api4 = "/devices/auth-challenge" ascii
		$api5 = "/devices/receiver/Url" ascii
		$s1 = "sign_pdq.rs" ascii
		$s2 = "x-pdq-dateCredential=(.+?)/" ascii
		$s3 = "pdq-connect-agent" ascii
		$s4 = "PDQ Connect Agent" ascii
		$s5 = "PDQConnectAgent" ascii
		$s6 = "PDQConnectAgentsrc\\logger.rs" ascii
		$s7 = "-PDQ-Key-IdsUser-Agent" ascii
		$s8 = "\\PDQ\\PDQConnectAgent\\" ascii
		$s9 = "\\pdq_connect_agent.pdb" ascii
		$s10 = "task_ids[]PDQ rover" ascii
		$s11 = "https://app.pdq.com/" ascii

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0xcfd0) and (4 of ($s*) or (3 of ($api*) and 1 of ($s*)))
}