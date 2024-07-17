import "pe"


rule DITEKSHEN_INDICATOR_RMM_Splashtopstreamer : FILE
{
	meta:
		description = "Detects Splashtop Streamer. Review RMM Inventory"
		author = "ditekSHen"
		id = "317f2be4-983f-5528-b629-75a13de7b411"
		date = "2023-11-16"
		modified = "2023-11-16"
		reference = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_rmm.yar#L385-L403"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "67181cd6ae071074c6bf35f44963c11c9ee9b7df242027c15b1e165d108f7b98"
		score = 75
		quality = 75
		tags = "FILE"
		clamav1 = "INDICATOR.Win.RMM.SplashtopStreamer"

	strings:
		$s1 = "\\slave\\workspace\\GIT_WIN_SRS_Formal\\Source\\irisserver\\" ascii
		$s2 = ".api.splashtop.com" wide
		$s3 = "Software\\Splashtop Inc.\\Splashtop" wide
		$s4 = "restarted the streamer.%nApp version: %1" wide
		$s5 = "Splashtop-Splashtop Streamer-" wide
		$s6 = "[RemoveStreamer] Send msg 2 cloud(%d:%d:%d)" wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}