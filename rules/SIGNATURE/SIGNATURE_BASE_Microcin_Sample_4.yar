import "pe"


rule SIGNATURE_BASE_Microcin_Sample_4 : FILE
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		author = "Florian Roth (Nextron Systems)"
		id = "8a6a0735-422a-5e91-9274-ce55f7bee5d3"
		date = "2017-09-26"
		modified = "2023-12-05"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_microcin.yar#L70-L90"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "1293fbd1a6b440168bb1d7b250df0c8a1a7f99a7fb603a6abec7fe7ba20cf4f5"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "92c01d5af922bdaacb6b0b2dfbe29e5cc58c45cbee5133932a499561dab616b8"

	strings:
		$s1 = "cmd /c dir /a /s \"%s\" > \"%s\"" fullword wide
		$s2 = "ini.dat" fullword wide
		$s3 = "winupdata" fullword wide
		$f1 = "%s\\(%08x%08x)%s" fullword wide
		$f2 = "%s\\d%08x\\d%08x.db" fullword wide
		$f3 = "%s\\u%08x\\u%08x.db" fullword wide
		$f4 = "%s\\h%08x\\h%08x.db" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of ($s*) or 5 of them )
}