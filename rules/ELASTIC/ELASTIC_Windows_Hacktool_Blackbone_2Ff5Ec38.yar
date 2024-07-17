
rule ELASTIC_Windows_Hacktool_Blackbone_2Ff5Ec38 : FILE
{
	meta:
		description = "Detects Windows Hacktool Blackbone (Windows.Hacktool.BlackBone)"
		author = "Elastic Security"
		id = "2ff5ec38-ce35-432a-8ffa-d459f84438dd"
		date = "2022-04-04"
		modified = "2022-04-04"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Hacktool_BlackBone.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "4e3887f950bff034efedd40f1e949579854a24140128246fa6141f2c34de6017"
		logic_hash = "0c32bd04460cdf7a56664253992a684c2c684b15ac9ca853b27ab24f07f71607"
		score = 75
		quality = 75
		tags = "FILE"
		fingerprint = "e3df60931c040081214296f006d98e155a5dc7e285a840a1decb23186ef67465"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$str1 = "BlackBone: %s: ZwCreateThreadEx hThread 0x%X"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}