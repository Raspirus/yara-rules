rule SIGNATURE_BASE_HKTL_Unlicensed_Cobaltstrike_EICAR_Jul18_5 : FILE
{
	meta:
		description = "Detects strings found in CobaltStrike shellcode"
		author = "Florian Roth (Nextron Systems)"
		id = "d52536b8-dd6b-59be-8761-d22b6a279114"
		date = "2018-07-28"
		modified = "2021-06-17"
		reference = "https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_darkhydrus.yar#L69-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d066f22e01f9ca3a33c669552046a5ab8dd9e579236974b1c468ba9644498951"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "cec36e8ed65ac6f250c05b4a17c09f58bb80c19b73169aaf40fa15c8d3a9a6a1"

	strings:
		$x1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		$s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii
		$s2 = "libgcj-12.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and (pe.imphash()=="829da329ce140d873b4a8bde2cbfaa7e" or all of ($s*) or $x1)
}