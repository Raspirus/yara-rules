
rule SBOUSSEADEN_Cve_2019_1458 : FILE
{
	meta:
		description = "No description has been set in the source file - SBousseaden"
		author = "SBousseaden"
		id = "7bcbfccb-2db0-5438-9ed1-eee4c92710b6"
		date = "2020-10-23"
		modified = "2020-10-23"
		reference = "https://github.com/unamer/CVE-2019-1458"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/hunt_cve_2019_1458.yara#L1-L22"
		license_url = "N/A"
		logic_hash = "8c5eac6b9fb9f87e0ffb219f0af8f83475799e062ed339da7a0525180292f5f2"
		score = 75
		quality = 75
		tags = "FILE"

	strings:
		$s1 = "RtlGetVersion"
		$s2 = {45 33 C9 BA 03 80 00 00 33 C9}
		$s3 = "SploitWnd"
		$s4 = "CreateWindowExW"
		$s5 = "GetKeyboardState"
		$s6 = "SetKeyboardState"
		$s7 = "SetWindowLongPtrW"
		$s9 = "SetClassLongPtrW"
		$s10 = "DestroyWindow"
		$s11 = "CreateProcess"
		$s12 = {4C 8B D1 8B 05 ?? ?? ?? 00 0F 05 C3}
		$s13 = {80 10 00 00 09 10}
		$s14 = "NtUserMessageCall"
		$s15 = "HMValidateHandle"
		$s16 = "IsMenu"

	condition:
		uint16(0)==0x5a4d and all of them
}