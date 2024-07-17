import "pe"


rule SIGNATURE_BASE_Suckfly_Nidiran_Gen_2 : FILE
{
	meta:
		description = "Detects Suckfly Nidiran Trojan"
		author = "Florian Roth (Nextron Systems)"
		id = "b090079d-1c22-5931-a25b-e960343a610f"
		date = "2018-01-28"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_suckfly.yar#L31-L59"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "2e4f6a920e063113a9ff252869e1c2ebdf5a2495b4adb1edaf9500904234f362"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b53a316a03b46758cb128e5045dab2717cb36e7b5eb1863ce2524d4f69bc2cab"
		hash2 = "eaee2bf83cf90d35dab8a4711f7a5f2ebf9741007668f3746995f4564046fbdf"

	strings:
		$x1 = "WorkDll.dll" fullword ascii
		$x2 = "%userprofile%\\Security Center\\secriter.dll" fullword ascii
		$s1 = "DLL_PROCESS_ATTACH is called" fullword ascii
		$s2 = "Support Security Accounts Manager For Microsoft Windows.If this service is stopped, any services that depended on it will fail t" ascii
		$s3 = "before CreateRemoteThread" fullword ascii
		$s4 = "CreateRemoteThread Succ" fullword ascii
		$s5 = "Microsoft Security Accounts Manager" fullword ascii
		$s6 = "DoRunRemote" fullword ascii
		$s7 = "AutoRunFun" fullword ascii
		$s8 = "ServiceMain is called" fullword ascii
		$s9 = "DllRegisterServer is called" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (1 of ($x*) or 4 of them )
}