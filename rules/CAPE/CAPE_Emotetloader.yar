rule CAPE_Emotetloader : FILE
{
	meta:
		description = "Emotet Loader"
		author = "kevoreilly"
		id = "aea8ff2e-bdf7-5417-a41c-93566d1dd019"
		date = "2022-05-31"
		modified = "2022-05-31"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/EmotetLoader.yar#L1-L12"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "410872d25ed3a89a2cba108f952d606cd1c3bf9ccc89ae6ab3377b83665c2773"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "EmotetLoader Payload"

	strings:
		$antihook = {8B 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 95 28 FF FF FF A1 ?? ?? ?? ?? 2D 4D 01 00 00 A3 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 3B 0D ?? ?? ?? ?? 76 26 8B 95 18 FF FF FF 8B 42 38}

	condition:
		uint16(0)==0x5A4D and any of them
}