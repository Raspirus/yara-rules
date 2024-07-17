
rule SIGNATURE_BASE_APT_MAL_Ke3Chang_Ketrican_Jun20_1 : FILE
{
	meta:
		description = "Detects Ketrican malware"
		author = "Florian Roth (Nextron Systems)"
		id = "ccd8322e-c822-512a-9ac5-eabc9d09640b"
		date = "2020-06-18"
		modified = "2023-12-05"
		reference = "BfV Cyber-Brief Nr. 01/2020"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ke3chang.yar#L23-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "a2806de18432dbab24f08c7c2863fd694c91192cf7df4388dfeb87b237f22257"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "02ea0bc17875ab403c05b50205389065283c59e01de55e68cee4cf340ecea046"
		hash2 = "f3efa600b2fa1c3c85f904a300fec56104d2caaabbb39a50a28f60e0fdb1df39"

	strings:
		$xc1 = { 00 59 89 85 D4 FB FF FF 8B 85 D4 FB FF FF 89 45
               FC 68 E0 58 40 00 8F 45 FC E9 }
		$op1 = { 6a 53 58 66 89 85 24 ff ff ff 6a 79 58 66 89 85 }
		$op2 = { 8d 45 bc 50 53 53 6a 1c 8d 85 10 ff ff ff 50 ff }

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 1 of ($x*) or 2 of them
}