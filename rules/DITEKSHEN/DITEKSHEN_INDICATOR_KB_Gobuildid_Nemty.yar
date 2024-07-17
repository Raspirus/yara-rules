
rule DITEKSHEN_INDICATOR_KB_Gobuildid_Nemty : FILE
{
	meta:
		description = "Detects Golang Build IDs in known bad samples"
		author = "ditekSHen"
		id = "512fe910-e38c-513c-b678-a0592bdc4ae2"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_knownbad_id.yar#L1575-L1588"
		license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
		logic_hash = "246766ab1d2871b5c22323f622d39ce9fa9b46a2d43bace122ed5549484f3aac"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "Go build ID: \"R6dvaUktgv2SjVXDoMdo/kKgwagwoLRC88DpIXAmx/eipNq7_PQCTCOhZ6Q74q/RHJkCaNdTbd6qgYiA-EC\"" ascii
		$s2 = "Go build ID: \"vsdndTwlj03gbEoDu06S/anJkXGh7N08537M0RMms/VG58d99axcdeD_z1JIko/tfDVbCdWUId-VX90kuT7\"" ascii
		$s3 = "Go build ID: \"FG9JEesXBQ04oNCv2bIS/MmjCdGa3ogU_6DIz6bZR/AjrqKBSezDfY1t7U9xr-/-06dIpZsukiVcN0PtOCb\"" ascii
		$s4 = "Go build ID: \"MJ8bS1emWrrlXiE_C61E/A6GaZzhLls_pFKMGfU1H/ZgswGQy_lzK-I4cZykwm/8JzjhV06jZosSa5Qih5O\"" ascii
		$s5 = "Go build ID: \"_vQalVQKn2O8kxxA4vVM/slXlklhnjEF5tawjlPzW/t26rDRURK6ii0MqU7gIx/MNq6vj_uM15RhjVC2QuX\"" ascii
		$s6 = "Go build ID: \"KWssFDTp6mq16xlI5c0t/mQLgof0oyp-eYKqNYUFL/Np8S71zE5W5_BsJCpjsj/hXpFDaVCtay2509R05fd\"" ascii

	condition:
		uint16(0)==0x5a4d and 1 of them
}