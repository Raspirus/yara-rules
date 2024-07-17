
rule CAPE_Qakbot5 : FILE
{
	meta:
		description = "QakBot v5 Payload"
		author = "kevoreilly, enzok"
		id = "48866cdd-f60e-50b8-85f9-573710934b0b"
		date = "2024-04-28"
		modified = "2024-04-28"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/QakBot.yar#L1-L15"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		hash = "59559e97962e40a15adb2237c4d01cfead03623aff1725616caeaa5a8d273a35"
		logic_hash = "cc23a92f45619d44af824128b743c259dd9dfa7cb5106932f3425f3dfd1dccdf"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "QakBot Payload"
		packed = "f4bb0089dcf3629b1570fda839ef2f06c29cbf846c5134755d22d419015c8bd2"

	strings:
		$loop = {8B 75 ?? 48 8B 4C [2] FF 15 [4] 48 8B 4C [2] 48 8B 01 FF 50 ?? 8B DE 48 8B 4C [2] 48 85 C9 0F 85 [4] EB 4E}
		$c2list = {0F B7 1D [4] B? [2] 00 00 E8 [4] 8B D3 4? 89 45 ?? 4? 33 C9 4? 8D 0D [4] 4? 8B C0 4? 8B F8 E8}
		$campaign = {0F B7 1D [4] B? [2] 00 00 E8 [4] 8B D3 4? 89 44 24 ?? 4? 33 C9 4? 8D 0D [4] 4? 8B C0 4? 8B F8 E8}

	condition:
		uint16(0)==0x5A4D and 2 of them
}