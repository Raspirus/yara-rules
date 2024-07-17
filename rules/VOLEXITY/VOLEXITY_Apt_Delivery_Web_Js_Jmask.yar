rule VOLEXITY_Apt_Delivery_Web_Js_Jmask : EVILBAMBOO FILE
{
	meta:
		description = "Detects the JMASK profiling script in its minified // obfuscated format."
		author = "threatintel@volexity.com"
		id = "a7b653e1-f7c6-56cc-ab99-3de91d29ef3b"
		date = "2023-06-15"
		modified = "2023-09-21"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2023/2023-09-22 EvilBamboo/indicators/rules.yar#L446-L472"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "64315ac05049954d36297a616a25ffdd7ce81c6313c0878d5ba4082da24c21bb"
		score = 75
		quality = 80
		tags = "EVILBAMBOO, FILE"
		hash1 = "efea95720853e0cd2d9d4e93a64a726cfe17efea7b17af7c4ae6d3a6acae5b30"
		scan_context = "file"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$rev0 = "oi.buhtig.ralue//:ptth" ascii
		$rev1 = "lairA' xp41" ascii
		$rev2 = "dnuof ton ksaMateM" ascii
		$unicode1 = "document[\"\\u0063\\u0075\\u0072\\u0072\\u0065\\u006e\\u0074\\u0053\\u0063\\u0072\\u0069\\u0070\\u0074\"]" ascii
		$unicode2 = "\\u0061\\u0070\\u0070\\u006c\\u0069\\u0063\\u0061\\u0074\\u0069\\u006f\\u006e\\u002f\\u006a\\u0073\\u006f\\u006e" ascii
		$unicode3 = "\\u0063\\u006c\\u0069\\u0065\\u006e\\u0074\\u0057\\u0069\\u0064\\u0074\\u0068" ascii
		$unicode4 = "=window[\"\\u0073\\u0063\\u0072\\u0065\\u0065\\u006e\"]" ascii
		$header = "(function(){info={};finished=" ascii

	condition:
		all of ($rev*) or all of ($unicode*) or $header
}