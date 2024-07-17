
rule SIGNATURE_BASE_MAL_ME_Rawdisk_Agent_Jan20_2 : FILE
{
	meta:
		description = "Detects suspicious malware using ElRawDisk"
		author = "Florian Roth (Nextron Systems)"
		id = "9817fb22-7bed-5869-aa92-66c458b81c7f"
		date = "2020-01-02"
		modified = "2022-12-21"
		reference = "https://twitter.com/jfslowik/status/1212501454549741568?s=09"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_dustman.yar#L26-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "73e4a88b749e3b2654e9021290932d2e556c29cfa772785b23bebad9f3a3f90a"
		score = 65
		quality = 85
		tags = "FILE"
		hash1 = "44100c73c6e2529c591a10cd3668691d92dc0241152ec82a72c6e63da299d3a2"

	strings:
		$x1 = "\\Release\\Dustman.pdb" ascii
		$x2 = "/c agent.exe A" fullword ascii
		$s1 = "C:\\windows\\system32\\cmd.exe" fullword ascii
		$s2 = "The Magic Word!" fullword ascii
		$s3 = "Software\\Oracle\\VirtualBox" fullword wide
		$s4 = "\\assistant.sys" wide
		$s5 = "Down With Bin Salman" fullword wide
		$sc1 = { 00 5C 00 5C 00 2E 00 5C 00 25 00 73 }
		$op1 = { 49 81 c6 ff ff ff 7f 4c 89 b4 24 98 }

	condition:
		uint16(0)==0x5a4d and filesize <=3000KB and (1 of ($x*) or 3 of them )
}