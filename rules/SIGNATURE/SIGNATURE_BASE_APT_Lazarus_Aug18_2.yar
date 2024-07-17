rule SIGNATURE_BASE_APT_Lazarus_Aug18_2 : FILE
{
	meta:
		description = "Detects Lazarus Group Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "3c77d603-6443-5e78-8a8a-a89112619aa6"
		date = "2018-08-24"
		modified = "2023-12-05"
		reference = "https://securelist.com/operation-applejeus/87553/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_applejeus.yar#L62-L82"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "75d52ad829383392d9eb20a8308278d073d16f7624e60010356534bdc6acc81f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8ae766795cda6336fd5cad9e89199ea2a1939a35e03eb0e54c503b1029d870c4"
		hash2 = "d3ef262bae0beb5d35841d131b3f89a9b71a941a86dab1913bda72b935744d2e"

	strings:
		$s1 = "vAdvapi32.dll" fullword wide
		$s2 = "lws2_32.dll" fullword wide
		$s3 = "%s %s > \"%s\" 2>&1" fullword wide
		$s4 = "Not Service" fullword wide
		$s5 = "ping 127.0.0.1 -n 3" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (4 of them )
}