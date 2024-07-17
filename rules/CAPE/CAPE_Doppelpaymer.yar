rule CAPE_Doppelpaymer : FILE
{
	meta:
		description = "DoppelPaymer Payload"
		author = "kevoreilly"
		id = "c8178906-1722-5908-9ad4-7ee1eef39138"
		date = "2022-06-27"
		modified = "2022-06-27"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/DoppelPaymer.yar#L1-L13"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "73a2575671bafc31a70af3ce072d6f94ae172b12202baebba586a02524cb6f9d"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "DoppelPaymer Payload"

	strings:
		$getproc32 = {81 FB ?? ?? ?? ?? 74 2D 8B CB E8 ?? ?? ?? ?? 85 C0 74 0C 8B C8 8B D7 E8 ?? ?? ?? ?? 5B 5F C3}
		$cmd_string = "Setup run\\n" wide

	condition:
		uint16(0)==0x5A4D and all of them
}