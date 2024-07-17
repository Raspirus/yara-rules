import "pe"


import "pe"


import "pe"


import "pe"


rule SIGNATURE_BASE_MAL_3Cxdesktopapp_Macos_Backdoor_Mar23 : FILE
{
	meta:
		description = "Detects 3CXDesktopApp MacOS Backdoor component"
		author = "X__Junior (Nextron Systems)"
		id = "80046c8e-0c2a-5885-b140-a6084f48160d"
		date = "2023-03-30"
		modified = "2023-12-05"
		reference = "https://www.volexity.com/blog/2023/03/30/3cx-supply-chain-compromise-leads-to-iconic-incident/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_mal_3cx_compromise_mar23.yar#L251-L275"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
		logic_hash = "777a0a29c376f3697021dd627e716c31bda7933c5f40a8fe79b80e3cea46ce43"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$sa1 = "%s/.main_storage" ascii fullword
		$sa2 = "%s/UpdateAgent" ascii fullword
		$op1 = { 31 C0 41 80 34 06 ?? 48 FF C0 48 83 F8 ?? 75 ?? BE ?? ?? ?? ?? BA ?? ?? ?? ?? 4C 89 F7 48 89 D9 E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? 4C 89 F7 5B 41 5E 41 5F E9 ?? ?? ?? ?? 5B 41 5E 41 5F C3}
		$op2 = { 0F 11 84 24 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 0F 29 84 24 ?? ?? ?? ?? 0F 28 05 ?? ?? ?? ?? 0F 29 84 24 ?? ?? ?? ?? 31 C0 80 B4 04 ?? ?? ?? ?? ?? 48 FF C0}

	condition:
		(( uint16(0)==0xfeca or uint16(0)==0xfacf or uint32(0)==0xbebafeca) and filesize <6MB and ((1 of ($sa*) and 1 of ($op*)) or all of ($sa*))) or ( all of ($op*))
}