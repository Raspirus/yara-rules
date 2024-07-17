import "pe"


rule DITEKSHEN_INDICATOR_RMM_Fleetdeck_Commander_Launcher : FILE
{
	meta:
		description = "Detects FleetDeck Commander Launcher. Review RMM Inventory"
		author = "ditekSHen"
		id = "9a4a221e-7a7a-5008-b509-7f01e4a3eea6"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L164-L178"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "9429f55f162eebc58a7a9af8706244438cb76b1f0987facbb52d29997ed48b95"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.FleetDeckCommander-Launcher"

	strings:
		$s1 = "fleetdeck.io/prototype3/commander_launcher" ascii
		$s2 = "FleetDeck Commander Launcher" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}