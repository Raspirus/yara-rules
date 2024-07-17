rule SIGNATURE_BASE_MAL_LNX_Redmenshen_Bpfdoor_May23_1 : FILE
{
	meta:
		description = "Detects BPFDoor malware"
		author = "Florian Roth"
		id = "25df4dba-ec6e-5999-b6be-56fe933cb0d0"
		date = "2023-05-11"
		modified = "2023-12-05"
		reference = "https://www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/mal_lnx_implant_may22.yar#L3-L42"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c58971a43443800256e791b4f9fe7c3221518b0050e5f2964b6c843ddb4549ac"
		score = 80
		quality = 85
		tags = "FILE"
		hash1 = "afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7"

	strings:
		$x1 = "[-] Execute command failed" ascii fullword
		$x2 = "/var/run/initd.lock" ascii fullword
		$xc1 = { 2F 00 3E 3E 00 65 78 69 74 00 72 00 }
		$sc1 = { 9F CD 30 44 }
		$sc2 = { 66 27 14 5E }
		$sa1 = "TLS-CHACHA20-POLY1305-SHA256" ascii fullword
		$sop1 = { 48 83 c0 01 4c 39 f8 75 ea 4c 89 7c 24 68 48 69 c3 d0 00 00 00 48 8b 5c 24 50 48 8b 54 24 78 48 c7 44 24 38 00 00 00 00 }
		$sop2 = { 48 89 de f3 a5 89 03 8b 44 24 2c 39 44 24 28 44 89 4b 04 48 89 53 10 0f 95 c0 }
		$sop3 = { 49 d3 cd 4d 31 cd b1 29 49 89 e9 49 d3 c8 4d 31 c5 4c 03 68 10 48 89 f9 }

	condition:
		uint16(0)==0x457f and filesize <900KB and ((1 of ($x*) and 1 of ($s*)) or 4 of them or ( all of ($sc*) and $sc1 in (@sc2[1]-50..@sc2[1]+50))) or (2 of ($x*) or 5 of them )
}