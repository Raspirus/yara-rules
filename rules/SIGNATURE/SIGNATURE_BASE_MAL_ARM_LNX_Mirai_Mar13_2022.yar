
rule SIGNATURE_BASE_MAL_ARM_LNX_Mirai_Mar13_2022 : FILE
{
	meta:
		description = "Detects new ARM Mirai variant"
		author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
		id = "54d8860e-fc45-5571-b68c-66590c67a705"
		date = "2022-03-16"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_mirai.yar#L159-L181"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a44a6174a198a658c8a5e2da50192da20bae7f8ed4e4f212c9eebb29fa4b0dd0"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "0283b72913b8a78b2a594b2d40ebc3c873e4823299833a1ff6854421378f5a68"

	strings:
		$str1 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
		$str2 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm/lib1funcs.asm"
		$str3 = "/home/landley/aboriginal/aboriginal/build/temp-armv6l/gcc-core/gcc/config/arm"
		$str4 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv6l/bin/../cc/include"
		$attck1 = "attack.c"
		$attck2 = "attacks.c"
		$attck3 = "anti_gdb_entry"
		$attck4 = "resolve_cnc_addr"
		$attck5 = "attack_gre_eth"
		$attck6 = "attack_udp_generic"
		$attck7 = "attack_get_opt_ip"
		$attck8 = "attack_icmpecho"

	condition:
		uint16(0)==0x457f and (3 of ($str*) or 4 of ($attck*))
}