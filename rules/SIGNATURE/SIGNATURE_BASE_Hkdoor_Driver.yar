import "pe"


rule SIGNATURE_BASE_Hkdoor_Driver : FILE
{
	meta:
		description = "Hacker's Door Driver"
		author = "Cylance Inc."
		id = "50b763a9-6d4f-59dd-ba6c-27e2ae117523"
		date = "2018-01-01"
		modified = "2023-01-07"
		reference = "https://www.cylance.com/en_us/blog/threat-spotlight-opening-hackers-door.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_hkdoor.yar#L81-L99"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "68ac505d67af5361f096529697e621c83a4628f21c213fcea6652905f87ebe00"
		score = 75
		quality = 83
		tags = "FILE"

	strings:
		$s1 = "ipfltdrv.sys" fullword ascii
		$s2 = "Patch Success." fullword ascii
		$s3 = "\\DosDevices\\kifes" ascii
		$s4 = "\\Device\\kifes" ascii
		$s5 = {75 28 22 36 30 5b 4a 77 7b 58 4d 6c 3f 73 63 5e 38 47 7c 7d 7a 40 3a 41 2a 45 4e 44 79 64 67 6d 65 74 21 39 23 3c 20 49 43 69 4c 3b 31 57 2f 55 3e 26 59 62 61 54 53 5a 2d 25 78 35 5c 76 3d 34 27 6b 5f 72 2c 32 4f 2b 71 66 42 33 37 56 52 60 5d 29 4b 51 2e 6f 50 68 6e 6a 24 48 7e 46 70}

	condition:
		uint16(0)==0x5a4d and pe.subsystem==pe.SUBSYSTEM_NATIVE and (4 of ($s*))
}