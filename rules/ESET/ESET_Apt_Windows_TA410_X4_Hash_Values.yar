import "pe"


import "pe"


import "pe"


import "pe"


import "pe"


rule ESET_Apt_Windows_TA410_X4_Hash_Values : FILE
{
	meta:
		description = "Matches X4 hash function found in TA410 X4"
		author = "ESET Research"
		id = "859bb977-82d0-5314-b1a8-fb3bb06a1b28"
		date = "2020-10-09"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/ta410/ta410.yar#L127-L149"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "bcf3891ff888ca99af9aa0e239b29241ae819022607fb829c5731267add308ea"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = {D1 10 76 C2 B6 03}
		$s2 = {71 3E A8 0D}
		$s3 = {DC 78 94 0E}
		$s4 = {40 0D E7 D6 06}
		$s5 = {83 BB FD E8 06}
		$s6 = {92 9D 9B FF EC 03}
		$s7 = {DD 0E FC FA F5 03}
		$s8 = {15 60 1E FB F5 03}

	condition:
		uint16(0)==0x5a4d and 4 of them
}