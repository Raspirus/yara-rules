
rule SIGNATURE_BASE_APT_Cobaltstrike_Beacon_Indicator : FILE
{
	meta:
		description = "Detects CobaltStrike beacons"
		author = "JPCERT"
		id = "8508c7a0-0131-59b1-b537-a6d1c6cb2b35"
		date = "2018-11-09"
		modified = "2023-12-05"
		reference = "https://github.com/JPCERTCC/aa-tools/blob/master/cobaltstrikescan.py"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_cobaltstrike.yar#L40-L52"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0f429a7a8c8bbea22eba3bbf81e391dab8e957583283a995d1d60d42f17c20e7"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$v1 = { 73 70 72 6E 67 00 }
		$v2 = { 69 69 69 69 69 69 69 69 }

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}