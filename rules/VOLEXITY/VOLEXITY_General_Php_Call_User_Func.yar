
rule VOLEXITY_General_Php_Call_User_Func : GENERAL WEBSHELLS
{
	meta:
		description = "Webshells using call_user_func against an object from a file input or POST variable."
		author = "threatintel@volexity.com"
		id = "48c7857e-7dda-5e3f-b82c-7d34c251f083"
		date = "2021-06-16"
		modified = "2022-07-28"
		reference = "https://zhuanlan.zhihu.com/p/354906657"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L154-L170"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "46c999da97682023861e58f9cd2c8651480db990a0361c1985c6d5c35b5bf0ea"
		score = 75
		quality = 80
		tags = "GENERAL, WEBSHELLS"
		hash1 = "40b053a2f3c8f47d252b960a9807b030b463ef793228b1670eda89f07b55b252"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 0

	strings:
		$s1 = "@call_user_func(new C()" wide ascii

	condition:
		$s1
}