import "pe"


rule DITEKSHEN_INDICATOR_RMM_Atera : FILE
{
	meta:
		description = "Detects Atera. Review RMM Inventory"
		author = "ditekSHen"
		id = "9801f5c9-bc1e-5502-8bca-ee1f5ca0f497"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L345-L366"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "dbc37a941b38d36ea9bc31880c3cba6cd2b88b534583e86741f7686fcb410235"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.Atera"

	strings:
		$s1 = "SOFTWARE\\ATERA Networks\\AlphaAgent" wide
		$s2 = "Monitoring & Management Agent by ATERA" ascii wide
		$s3 = "agent-api-{0}.atera.com" wide
		$s4 = "agent-api.atera.com" wide
		$s5 = "acontrol.atera.com" wide
		$s6 = /Agent\/(PingReply|GetCommandsFallback|GetCommands|GetTime|GetEnvironmentStatus|GetRecurringPackages|AgentStarting|AcknowledgeCommands)/ wide
		$s7 = "\\AlphaControlAgent\\obj\\Release\\AteraAgent.pdb" ascii
		$s8 = "AteraWebAddress" ascii
		$s9 = "AlphaControlAgent.CloudLogsManager+<>" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}