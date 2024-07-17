
rule CAPE_Conti : FILE
{
	meta:
		description = "Conti Ransomware"
		author = "kevoreilly"
		id = "c94aed07-0eaf-5b51-a81e-e1992543673a"
		date = "2021-03-15"
		modified = "2021-03-15"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/Conti.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "c9842f93d012d0189b9c6f10ad558b37ae66226bbb619ad677f6906ccaf0e848"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "Conti Payload"

	strings:
		$crypto1 = {8A 07 8D 7F 01 0F B6 C0 B9 ?? 00 00 00 2B C8 6B C1 ?? 99 F7 FE 8D [2] 99 F7 FE 88 ?? FF 83 EB 01 75 DD}
		$website1 = "https://contirecovery.info" ascii wide
		$website2 = "https://contirecovery.best" ascii wide

	condition:
		uint16(0)==0x5A4D and any of them
}