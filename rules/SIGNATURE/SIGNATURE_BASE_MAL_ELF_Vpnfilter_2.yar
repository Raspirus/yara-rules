rule SIGNATURE_BASE_MAL_ELF_Vpnfilter_2 : FILE
{
	meta:
		description = "Detects VPNFilter malware"
		author = "Florian Roth (Nextron Systems)"
		id = "95356303-e8ba-585d-b2fc-af9e10b0b93f"
		date = "2018-05-24"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_vpnfilter.yar#L33-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "238ec4575fd8adbfa592e07b601313c71a08be8c776e78469aef8ad02e411798"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "50ac4fcd3fbc8abcaa766449841b3a0a684b3e217fc40935f1ac22c34c58a9ec"

	strings:
		$s1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.2; Trident/4.0)" fullword ascii
		$s2 = "passwordPASSWORDpassword" fullword ascii
		$s3 = "/tmp/client.key" fullword ascii

	condition:
		uint16(0)==0x457f and filesize <1000KB and all of them
}