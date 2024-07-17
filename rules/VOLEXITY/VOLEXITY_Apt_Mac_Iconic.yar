
rule VOLEXITY_Apt_Mac_Iconic : UTA0040
{
	meta:
		description = "Detects the MACOS version of the ICONIC loader."
		author = "threatintel@volexity.com"
		id = "6d702ed3-e5b9-5324-a06b-507c9231cc00"
		date = "2023-03-30"
		modified = "2023-03-30"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2023/2023-03-30 3CX/indicators/rules.yar#L32-L50"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "7b689c3931632b01869ac2f21a1edca0a5ca9007299fe7cd16962d6866c27558"
		score = 75
		quality = 80
		tags = "UTA0040"
		hash1 = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$str1 = "3CX Desktop App" xor(0x01-0xff)
		$str2 = "__tutma=" xor(0x01-0xff)
		$str3 = "Mozilla/5.0" xor(0x01-0xff)

	condition:
		all of them
}