import "pe"


rule SIGNATURE_BASE_Turla_Kazuarrat : FILE
{
	meta:
		description = "Detects Turla Kazuar RAT described by DrunkBinary"
		author = "Markus Neis / Florian Roth"
		id = "147cc7b7-6dbd-51a2-9501-bcbaec32e20e"
		date = "2018-04-08"
		modified = "2023-12-05"
		reference = "https://twitter.com/DrunkBinary/status/982969891975319553"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla.yar#L173-L192"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d7f15fe8e33a9e3516eab5c3c5664aeee25d1d153f01b888a50dd2accba432ca"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "6b5d9fca6f49a044fd94c816e258bf50b1e90305d7dab2e0480349e80ed2a0fa"
		hash2 = "7594fab1aadc4fb08fb9dbb27c418e8bc7f08dadb2acf5533dc8560241ecfc1d"
		hash3 = "4e5a86e33e53931afe25a8cb108f53f9c7e6c6a731b0ef4f72ce638d0ea5c198"

	strings:
		$x1 = "~1.EXE" wide
		$s2 = "dl32.dll" fullword ascii
		$s3 = "HookProc@" ascii
		$s4 = "0`.wtf" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and (pe.imphash()=="682156c4380c216ff8cb766a2f2e8817" or 2 of them )
}