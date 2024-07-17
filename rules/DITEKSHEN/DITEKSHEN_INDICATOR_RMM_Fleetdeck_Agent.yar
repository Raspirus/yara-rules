rule DITEKSHEN_INDICATOR_RMM_Fleetdeck_Agent : FILE
{
	meta:
		description = "Detects FleetDeck Agent. Review RMM Inventory"
		author = "ditekSHen"
		id = "342a196c-1c5c-5951-85e4-d288311b4980"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L101-L123"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "121e59ea0088c519b618e740b57c560d60cced4a48c9d468e6bf1ab22fa8c8ff"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.FleetDeckAgent"

	strings:
		$s1 = "fleetdeck.io/" ascii
		$s2 = "load FleetDeck agent" ascii
		$s3 = ".dev1.fleetdeck.io" ascii
		$s4 = "remoteDesktopSessionMutex" ascii
		$s5 = "main.remoteDesktopWatchdog" fullword ascii
		$s6 = "main.virtualTerminalWatchdog" fullword ascii
		$s7 = "main.meetRemoteDesktop" fullword ascii
		$s8 = "repo.senri.se/prototype3/" ascii
		$s9 = "main.svcIpcClient" fullword ascii
		$s10 = "main.hookMqttLogging" fullword ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}