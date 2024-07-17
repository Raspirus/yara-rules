import "pe"


rule SIGNATURE_BASE_APT_APT41_HIGHNOON_BIN_2 : FILE
{
	meta:
		description = "Detects APT41 malware HIGHNOON.BIN"
		author = "Florian Roth (Nextron Systems)"
		id = "37d6a44d-7811-5e87-84e2-b2a8b3da3124"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt41.yar#L182-L200"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1e3d622b4719962f59d95dbf1374c526c22461dd1d9313504f28e8e5c9184272"
		score = 85
		quality = 85
		tags = "FILE"
		hash1 = "63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7"
		hash2 = "c51c5bbc6f59407286276ce07f0f7ea994e76216e0abe34cbf20f1b1cbd9446d"

	strings:
		$x1 = "\\Double\\Door_wh\\" ascii
		$x2 = "[Stone] Config --> 2k3 TCP Positive Logout." fullword ascii
		$x3 = "\\RbDoorX64.pdb" ascii
		$x4 = "RbDoor, Version 1.0" fullword wide
		$x5 = "About RbDoor" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of them
}