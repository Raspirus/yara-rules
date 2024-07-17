import "pe"


rule SIGNATURE_BASE_Microcin_Sample_2 : FILE
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		author = "Florian Roth (Nextron Systems)"
		id = "8718ef84-be2b-55a6-a4bb-41161548a2b4"
		date = "2017-09-26"
		modified = "2023-12-05"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_microcin.yar#L38-L52"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "99feb3e1672f69c4cf41a100e9ba64421fd75c3554306a1bf1475da6f1e14ed1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8a7d04229722539f2480270851184d75b26c375a77b468d8cbad6dbdb0c99271"

	strings:
		$s2 = "[Pause]" fullword ascii
		$s7 = "IconCache_%02d%02d%02d%02d%02d" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}