import "pe"


rule DITEKSHEN_INDICATOR_RMM_Fleetdeck_Commander : FILE
{
	meta:
		description = "Detects FleetDeck Commander. Review RMM Inventory"
		author = "ditekSHen"
		id = "27d533b5-7a66-507e-8ef8-ad9a6cd39ab1"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L125-L143"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "feee888c6649af0d8e8b08a38dda0bf7970089cf064f58b8bd9c6ebd8378e094"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.FleetDeckCommander"

	strings:
		$s1 = "Software\\Microsoft\\FleetDeck Commander" ascii
		$s2 = "fleetdeck.io/prototype3/" ascii
		$s3 = "fleetdeck_commander_launcher.exe" ascii
		$s4 = "fleetdeck_commander_svc.exe" ascii
		$s5 = "|FleetDeck Commander" ascii
		$s6 = "c:\\agent\\_work\\66\\s\\" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}