rule VOLEXITY_Trojan_Any_Pupyrat_B : COMMODITY
{
	meta:
		description = "Detects the PUPYRAT malware family, a cross-platform RAT written in Python."
		author = "threatintel@volexity.com"
		id = "1da1e5ba-cf00-5935-b3d1-0ff2713b7e34"
		date = "2022-04-07"
		modified = "2022-07-28"
		reference = "https://github.com/n1nj4sec/pupy"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L101-L134"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		logic_hash = "65eebfea2338deed682693f048a88d46ea4621177acb77c0642583b0dc35c818"
		score = 75
		quality = 80
		tags = "COMMODITY"
		hash1 = "7474a6008b99e45686678f216af7d6357bb70a054c6d9b05e1817c8d80d536b4"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 1

	strings:
		$elf1 = "LD_PRELOAD=%s HOOK_EXIT=%d CLEANUP=%d exec %s 1>/dev/null 2>/dev/null" ascii
		$elf2 = "reflective_inject_dll" fullword ascii
		$elf3 = "ld_preload_inject_dll" fullword ascii
		$pupy1 = "_pupy.error" ascii
		$pupy2 = "_pupy" ascii
		$pupy3 = "pupy://" ascii
		$s1 = "Args not passed" ascii
		$s2 = "Too many args" ascii
		$s3 = "Can't execute" ascii
		$s4 = "mexec:stdin" ascii
		$s5 = "mexec:stdout" ascii
		$s6 = "mexec:stderr" ascii
		$s7 = "LZMA error" ascii

	condition:
		any of ($elf*) or all of ($pupy*) or all of ($s*)
}