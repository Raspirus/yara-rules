
rule SIGNATURE_BASE_M_APT_Downloader_BOOMMIC : FILE
{
	meta:
		description = "Rule looking for BOOMMIC malware"
		author = "Mandiant"
		id = "34ea08a6-5d6f-5cdd-a629-fa36313c98f7"
		date = "2022-04-28"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/tracking-apt29-phishing-campaigns"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt29_nobelium_apr22.yar#L19-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c561b19464597f896d31307c0383fbc639cf4211600513e1251a3f59405bfed6"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$loc_10001000 = { 55 8B EC 8D 45 0C 50 8B 4D 08 51 6A 02 FF 15 [4] 85 C0 74 09 B8 01 00 00 00 EB 04 EB 02 33 C0 5D C3 }
		$loc_100012fd = {6A 00 8D 55 EC 52 8B 45 D4 50 6A 05 8B 4D E4 51 FF 15 }
		$func1 = "GetComputerNameExA" ascii
		$func2 = "HttpQueryInfoA" ascii

	condition:
		uint16(0)==0x5a4d and uint32( uint32(0x3C))==0x00004550 and filesize <1MB and (($loc_10001000 and $func1) or ($loc_100012fd and $func2))
}