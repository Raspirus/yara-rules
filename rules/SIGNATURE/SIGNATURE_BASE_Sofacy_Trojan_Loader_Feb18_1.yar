import "pe"


rule SIGNATURE_BASE_Sofacy_Trojan_Loader_Feb18_1 : FILE
{
	meta:
		description = "Sofacy Activity Feb 2018"
		author = "Florian Roth (Nextron Systems)"
		id = "358d7a77-0ff5-572e-9cd8-b2cebaace02f"
		date = "2018-03-01"
		modified = "2023-12-05"
		reference = "https://www.reverse.it/sample/e3399d4802f9e6d6d539e3ae57e7ea9a54610a7c4155a6541df8e94d67af086e?environmentId=100"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sofacy.yar#L29-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b1946af23fa0de69f5631a66fa211dab5d8731b5afdb23898428842232752e77"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "335565711db93cd02d948f472c51598be4d62d60f70f25a20449c07eae36c8c5"

	strings:
		$x1 = "%appdata%\\nad.dll" fullword wide
		$s3 = "%appdata%\\nad.bat" fullword wide
		$s1 = "apds.dll" fullword ascii
		$s2 = "nad.dll\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="a2d1be6502b4b3c28959a4fb0196ea45" or pe.exports("VidBitRpl") or 1 of ($x*) or 2 of them )
}