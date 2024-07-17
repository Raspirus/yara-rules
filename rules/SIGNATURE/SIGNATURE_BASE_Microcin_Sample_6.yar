import "pe"


rule SIGNATURE_BASE_Microcin_Sample_6 : FILE
{
	meta:
		description = "Malware sample mentioned in Microcin technical report by Kaspersky"
		author = "Florian Roth (Nextron Systems)"
		id = "9988723f-a7ca-598f-9a6c-9f3915732117"
		date = "2017-09-26"
		modified = "2023-12-05"
		reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_microcin.yar#L112-L128"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "280fb17b5ed5ff1c8018e426969f75e18589eabeb2a20e0e623f206e72e8958d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "cbd43e70dc55e94140099722d7b91b07a3997722d4a539ecc4015f37ea14a26e"
		hash2 = "871ab24fd6ae15783dd9df5010d794b6121c4316b11f30a55f23ba37eef4b87a"

	strings:
		$s1 = "** ERROR ** %s: %s" fullword ascii
		$s2 = "TEMPDATA" fullword wide
		$s3 = "Bruntime error " fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and all of them )
}