
rule SIGNATURE_BASE_APT_MAL_Falsefont_Backdoor_Jan24 : FILE
{
	meta:
		description = "Detects FalseFont backdoor, related to Peach Sandstorm APT"
		author = "X__Junior, Jonathan Peters"
		id = "b6a3efff-2abf-5ac1-9a2b-c7b30b51f92c"
		date = "2024-01-11"
		modified = "2024-04-24"
		reference = "https://twitter.com/MsftSecIntel/status/1737895710169628824"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_peach_sandstorm.yar#L1-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "364275326bbfc4a3b89233dabdaf3230a3d149ab774678342a40644ad9f8d614"
		logic_hash = "9a1b3779b63dd7fa8ddc84067dec09542518e9acebbf5d3b45cb75ec4add1158"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "Agent.Core.WPF.App" ascii
		$x2 = "3EzuNZ0RN3h3oV7rzILktSHSaHk+5rtcWOr0mlA1CUA=" wide
		$x3 = "viOIZ9cX59qDDjMHYsz1Yw==" wide
		$sa1 = "StopSendScreen" wide
		$sa2 = "Decryption failed :(" wide
		$sb1 = "{0}     {1}     {2}     {3}" wide
		$sb2 = "\\BraveSoftware\\Brave-Browser\\User Data\\" wide
		$sb3 = "select * from logins" wide
		$sb4 = "Loginvault.db" wide
		$sb5 = "password_value" wide

	condition:
		uint16(0)==0x5a4d and (1 of ($x*) or all of ($sa*) or all of ($sb*) or (1 of ($sa*) and 4 of ($sb*)))
}