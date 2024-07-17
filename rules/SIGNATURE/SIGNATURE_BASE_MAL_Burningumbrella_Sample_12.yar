rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_12 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "805a00e7-2959-53d8-b769-0f8e54e1bbd5"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L180-L201"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "31798a39d10bfa4520d91e1f555302e9ac4e38d90f8bc27376a5e7e1ccfcc5e1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b9aba520eeaf6511877c1eec5f7d71e0eea017312a104f30d3b8f17c89db47e8"

	strings:
		$s1 = "%SystemRoot%\\System32\\qmgr.dll" fullword ascii
		$s2 = "rundll32.exe %s,Startup" fullword ascii
		$s3 = "nvsvcs.dll" fullword wide
		$s4 = "SYSTEM\\CurrentControlSet\\services\\BITS\\Parameters" fullword ascii
		$s5 = "http://www.sginternet.net 0" fullword ascii
		$s6 = "Microsoft Corporation. All rights reserved." fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <80KB and (pe.exports("SvcServiceMain") and 5 of them )
}