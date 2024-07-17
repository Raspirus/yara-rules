rule VOLEXITY_Webshell_Php_Str_Replace_Create_Func : WEBSHELLS GENERAL FILE
{
	meta:
		description = "Looks for obfuscated PHP shells where create_function() is obfuscated using str_replace and then called using no arguments."
		author = "threatintel@volexity.com"
		id = "e0a5965c-54c3-5699-a45b-58f7152574dd"
		date = "2022-04-04"
		modified = "2022-07-28"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L45-L73"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "6a9ded1f1a8e4b8ae5f3db06f71bec6e9f62b6126b7444408d6319a35ed23827"
		score = 75
		quality = 80
		tags = "WEBSHELLS, GENERAL, FILE"
		hash1 = "c713d13af95f2fe823d219d1061ec83835bf0281240fba189f212e7da0d94937"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 0

	strings:
		$php = "<?php"
		$s = "=str_replace(" ascii
		$anon_func = "(''," ascii

	condition:
		filesize <100KB and $php at 0 and for any i in (1..#s) : ( for any j in (1..#anon_func) : ( uint16be(@s[i]-2)== uint16be(@anon_func[j]-2)))
}