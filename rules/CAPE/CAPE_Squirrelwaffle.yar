
rule CAPE_Squirrelwaffle : FILE
{
	meta:
		description = "No description has been set in the source file - CAPE"
		author = "kevoreilly & R3MRUM"
		id = "0ae75f24-7a2a-57d3-8c6f-a61ac6cc08e7"
		date = "2021-10-13"
		modified = "2021-10-13"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/data/yara/CAPE/SquirrelWaffle.yar#L1-L11"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/25a2b8705316eaf5acc94e3080e51f889264aee6/LICENSE"
		logic_hash = "5f799333398421d537ec7a87ca94f6cc9cf1e53e55b353036a5132440990e500"
		score = 75
		quality = 70
		tags = "FILE"
		cape_type = "SquirrelWaffle Payload"

	strings:
		$code = {8D 45 ?? C6 45 ?? 00 0F 43 4D ?? 83 7D ?? 10 0F 43 45 ?? 8A 04 10 32 04 39 8D 4D ?? 0F B6 C0 50 6A 01 E8 [4] C6 45}
		$decode = {F7 75 ?? 83 7D ?? 10 8D 4D ?? 8D 45 ?? C6 45 ?? 00 0F 43 4D ?? 83 7D ?? 10 0F 43 45 ?? 8A 04 10 32 04 39}

	condition:
		uint16(0)==0x5A4D and all of them
}