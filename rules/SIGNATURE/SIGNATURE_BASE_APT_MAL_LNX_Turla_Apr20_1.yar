import "pe"


rule SIGNATURE_BASE_APT_MAL_LNX_Turla_Apr20_1 : FILE
{
	meta:
		description = "Detects Turla Linux malware"
		author = "Florian Roth (Nextron Systems)"
		id = "f21e7793-a7dd-5195-805d-963827b35808"
		date = "2020-04-05"
		modified = "2023-12-05"
		reference = "https://twitter.com/Int2e_/status/1246115636331319309"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla.yar#L252-L272"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d463f5a151bb0c3440d719b4c7c0d1ca34de1e0bed7fb9167ecf396607abd3ff"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
		hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"

	strings:
		$s1 = "/root/.hsperfdata" ascii fullword
		$s2 = "Desc|     Filename     |  size  |state|" ascii fullword
		$s3 = "IPv6 address %s not supported" ascii fullword
		$s4 = "File already exist on remote filesystem !" ascii fullword
		$s5 = "/tmp/.sync.pid" ascii fullword
		$s6 = "'gateway' supported only on ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel" ascii fullword

	condition:
		uint16(0)==0x457f and filesize <5000KB and 4 of them
}