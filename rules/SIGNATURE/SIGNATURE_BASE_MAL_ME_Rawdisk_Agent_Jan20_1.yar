rule SIGNATURE_BASE_MAL_ME_Rawdisk_Agent_Jan20_1 : FILE
{
	meta:
		description = "Detects suspicious malware using ElRawDisk"
		author = "Florian Roth (Nextron Systems)"
		id = "0efaae51-1407-5039-9e5a-9c2f13d6a971"
		date = "2020-01-02"
		modified = "2022-12-21"
		reference = "Saudi National Cybersecurity Authority - Destructive Attack DUSTMAN"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_dustman.yar#L2-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "90345b8358d72b6616c6277222fb1091cb3a88b844391ac3766e7d1ee1192fbe"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "44100c73c6e2529c591a10cd3668691d92dc0241152ec82a72c6e63da299d3a2"

	strings:
		$x1 = "\\drv\\agent.plain.pdb" ascii
		$x2 = " ************** Down With Saudi Kingdom, Down With Bin Salman ************** " fullword ascii
		$s1 = ".?AVERDError@@" fullword ascii
		$s2 = "b4b615c28ccd059cf8ed1abf1c71fe03c0354522990af63adf3c911e2287a4b906d47d" fullword wide
		$s3 = "\\\\?\\ElRawDisk" fullword wide
		$s4 = "\\??\\c:" wide
		$op1 = { e9 3d ff ff ff 33 c0 48 89 05 0d ff 00 00 48 8b }
		$op2 = { 0f b6 0c 01 88 48 34 48 8b 8d a8 }

	condition:
		uint16(0)==0x5a4d and filesize <=2000KB and (1 of ($x*) or 4 of them )
}