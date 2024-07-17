
rule SBOUSSEADEN_Shad0W_Beacon_16June : FILE
{
	meta:
		description = "Shad0w beacon compressed"
		author = "SBousseaden"
		id = "1229e84f-bf6e-5e87-9351-a48cd50397b0"
		date = "2020-06-16"
		modified = "2020-06-17"
		reference = "https://github.com/bats3c/shad0w"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/shad0w_beacon_16June.yara#L1-L13"
		license_url = "N/A"
		logic_hash = "c313e995d6eaae6d2ee63964f6fc94964065af7a61d7f304280d914e6f0dd548"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = {F2 AE ?? ?? ?? FF 15 ?? ?? 00 00 48 09 C0 74 09}
		$s2 = {33 2E 39 36 00 ?? ?? ?? 21 0D 24 0E 0A}
		$s3 = "VirtualProtect"
		$s4 = "GetProcAddress"

	condition:
		uint16(0)==0x5a4d and all of ($s*)
}