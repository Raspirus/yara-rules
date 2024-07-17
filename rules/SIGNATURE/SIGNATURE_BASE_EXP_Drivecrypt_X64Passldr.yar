
rule SIGNATURE_BASE_EXP_Drivecrypt_X64Passldr : FILE
{
	meta:
		description = "Detects DriveCrypt exploit"
		author = "Florian Roth (Nextron Systems)"
		id = "94594b4e-091d-5964-b2b4-5d7d44601b28"
		date = "2018-08-21"
		modified = "2023-01-06"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/vul_drivecrypt.yar#L19-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "573cd96f7f82788a3884cd4b4d91c739a890835c3ed1b3933af48ba5756cc5a6"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "c828304c83619e2cb9dab80305e5286aba91742dc550e1469d91812af27101a1"

	strings:
		$s1 = "\\x64\\x64passldr.pdb" ascii
		$s2 = "\\amd64\\x64pass.sys" wide
		$s3 = "\\\\.\\DCR" fullword ascii
		$s4 = "Open SC Mgr Error" fullword ascii
		$s5 = "thing is ok " fullword ascii
		$s6 = "x64pass" fullword wide
		$s7 = "%ws\\%ws\\Security" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 3 of them
}