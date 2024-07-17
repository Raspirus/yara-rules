import "pe"


rule SBOUSSEADEN_Shad0W_Beacon : FILE
{
	meta:
		description = "Shad0w beacon default suspicous strings"
		author = "SBousseaden"
		id = "e725172d-dd07-5027-ac85-86d366881856"
		date = "2020-06-04"
		modified = "2020-06-05"
		reference = "https://github.com/bats3c/shad0w"
		source_url = "https://github.com/sbousseaden/YaraHunts//blob/71b27a2a7c57c2aa1877a11d8933167794e2b4fb/shad0w.yara#L3-L15"
		license_url = "N/A"
		logic_hash = "9ea7cf72da0d93f607f58b61cc0fb5f3f114d4454101c69b08c59e6b61353550"
		score = 75
		quality = 73
		tags = "FILE"

	strings:
		$s1 = "LdrLoadD"
		$s2 = {53 65 74 50 72 2A 65 73 73 4D}
		$s3 = "Policy"

	condition:
		uint16(0)==0x5a4d and all of ($s*) and pe.sections[0].name=="XPU0" and pe.imports("winhttp.dll","WinHttpOpen")
}