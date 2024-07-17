
rule ARKBIRD_SOLG_APT_Sidewinder_Nov_2020_1 : FILE
{
	meta:
		description = "Detect Sidewinder DLL decoder algorithm"
		author = "Arkbird_SOLG"
		id = "9e948949-f38d-5a76-a34c-965ec9be070d"
		date = "2020-11-14"
		modified = "2020-11-15"
		reference = "https://twitter.com/hexfati/status/1325397305051148292"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-11-15/APT_SideWinder_Nov_2020_1.yar#L1-L12"
		license_url = "N/A"
		logic_hash = "661eb5510ff0aa59b38b2c023653f0a23867a2813d854fbd0a7a6b657d9ba671"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "8d7ad2c603211a67bb7abf2a9fe65aefc993987dc804bf19bafbefaaca066eaa"

	strings:
		$s = { 13 30 05 00 ?? 00 00 00 01 00 00 11 ?? ?? 00 00 ?? ?? ?? 00 00 [30-80] 2B 16 07 08 8F 1? }

	condition:
		uint16(0)==0x5a4d and filesize >3KB and $s
}