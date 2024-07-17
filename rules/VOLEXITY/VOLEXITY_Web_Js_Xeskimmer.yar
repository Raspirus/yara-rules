import "pe"


rule VOLEXITY_Web_Js_Xeskimmer : XEGROUP
{
	meta:
		description = "Detects JScript code using in skimming credit card details."
		author = "threatintel@volexity.com"
		id = "2c0911cf-a679-5d4e-baad-777745a28e27"
		date = "2021-11-17"
		modified = "2021-12-07"
		reference = "https://github.com/MBThreatIntel/skimmers/blob/master/null_gif_skimmer.js"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2021/2021-12-06 - XEGroup/indicators/yara.yar#L68-L97"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "cc46e9fab5f408fde13c3897d378a1a2e4acb448f40ca4935c19024ebdc252d7"
		score = 75
		quality = 80
		tags = "XEGROUP"
		hash1 = "92f9593cfa0a28951cae36755d54de63631377f1b954a4cb0474fa0b6193c537"
		memory_suitable = 0
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s1 = ".match(/^([3456]\\d{14,15})$/g" ascii
		$s2 = "^(p(wd|ass(code|wd|word)))" ascii
		$b1 = "c('686569676874')" ascii
		$b2 = "c('7769647468')" ascii
		$c1 = "('696D67')" ascii
		$c2 = "('737263')" ascii
		$magic = "d=c.charCodeAt(b),a+=d.toString(16);"

	condition:
		all of ($s*) or all of ($b*) or all of ($c*) or $magic
}