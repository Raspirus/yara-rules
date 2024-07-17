import "pe"


rule SIGNATURE_BASE_MAL_Turla_Sample_May18_1 : FILE
{
	meta:
		description = "Detects Turla samples"
		author = "Florian Roth (Nextron Systems)"
		id = "5052838f-a895-55cb-abcf-813465074127"
		date = "2018-05-03"
		modified = "2023-12-05"
		reference = "https://twitter.com/omri9741/status/991942007701598208"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla.yar#L228-L250"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "f5bb26bc787acb89fe5a337121aabc0cd15ed3fd5cbe64ef4e7031e04dc14fb1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4c49c9d601ebf16534d24d2dd1cab53fde6e03902758ef6cff86be740b720038"
		hash2 = "77cbd7252a20f2d35db4f330b9c4b8aa7501349bc06bbcc8f40ae13d01ae7f8f"

	strings:
		$x1 = "sc %s create %s binPath= \"cmd.exe /c start %%SystemRoot%%\\%s\">>%s" fullword ascii
		$x2 = "cmd.exe /c start %%SystemRoot%%\\%s" fullword ascii
		$x3 = "cmd.exe /c %s\\%s -s %s:%s:%s -c \"%s %s /wait 1\">>%s" fullword ascii
		$x4 = "Read InjectLog[%dB]********************************" fullword ascii
		$x5 = "%s\\System32\\011fe-3420f-ff0ea-ff0ea.tmp" fullword ascii
		$x6 = "**************************** Begin ini %s [%d]***********************************************" fullword ascii
		$x7 = "%s -o %s -i %s -d exec2 -f %s" fullword ascii
		$x8 = "Logon to %s failed: code %d(User:%s,Pass:%s)" fullword ascii
		$x9 = "system32\\dxsnd32x.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and 1 of them
}