rule SIGNATURE_BASE_MAL_RANSOM_Lorenz_May21_1 : FILE
{
	meta:
		description = "Detects Lorenz Ransomware samples"
		author = "Florian Roth (Nextron Systems)"
		id = "0b18a4a3-82da-574b-8d10-daf2176448b9"
		date = "2021-05-04"
		modified = "2023-12-05"
		reference = "Internal Research - DACH TE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_ransom_lorenz.yar#L1-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "aec940deb2c3bc099a50a2e8f014ae425d306d331078d9ac2abc2ec7b8bf572e"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "4b1170f7774acfdc5517fbe1c911f2bd9f1af498f3c3d25078f05c95701cc999"
		hash2 = "8258c53a44012f6911281a6331c3ecbd834b6698b7d2dbf4b1828540793340d1"
		hash3 = "c0c99b141b014c8e2a5c586586ae9dc01fd634ea977e2714fbef62d7626eb3fb"

	strings:
		$x1 = "process call create \"cmd.exe /c schtasks /Create /F /RU System /SC ONLOGON " ascii fullword
		$x2 = "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCn7fL/1qsWkJkUtXKZIJNqYfnVByVhK" ascii fullword
		$s1 = "process call create \"cmd.exe /c schtasks /Create /F " ascii fullword
		$s2 = "twr.ini" ascii fullword
		$s3 = "/c wmic /node:'" ascii fullword
		$op1 = { 0f 4f d9 81 ff dc 0f 00 00 5f 8d 4b 0? 0f 4e cb 83 fe 3c 5e 5b }
		$op2 = { 6a 02 e8 ?? ?? 0? 00 83 c4 18 83 f8 01 75 01 cc 6a 00 68 ?? ?? 00 00 }

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and (1 of ($x*) or all of ($op*) or 3 of them )
}