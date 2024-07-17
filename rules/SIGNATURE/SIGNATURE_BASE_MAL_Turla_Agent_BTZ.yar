import "pe"


rule SIGNATURE_BASE_MAL_Turla_Agent_BTZ : FILE
{
	meta:
		description = "Detects Turla Agent.BTZ"
		author = "Florian Roth (Nextron Systems)"
		id = "bd642f11-19f6-5178-b978-1215215fea86"
		date = "2018-04-12"
		modified = "2023-01-06"
		reference = "https://www.gdatasoftware.com/blog/2014/11/23937-the-uroburos-case-new-sophisticated-rat-identified"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_turla.yar#L195-L226"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "3a091d29ef5981b9ab9c0e4114fef9de70acbcbc8ea8518183a567459e1086fa"
		score = 90
		quality = 85
		tags = "FILE"
		hash1 = "c4a1cd6916646aa502413d42e6e7441c6e7268926484f19d9acbf5113fc52fc8"

	strings:
		$x1 = "1dM3uu4j7Fw4sjnbcwlDqet4F7JyuUi4m5Imnxl1pzxI6as80cbLnmz54cs5Ldn4ri3do5L6gs923HL34x2f5cvd0fk6c1a0s" fullword ascii
		$x3 = "mstotreg.dat" fullword ascii
		$x4 = "Bisuninst.bin" fullword ascii
		$x5 = "mfc42l00.pdb" fullword ascii
		$x6 = "ielocal~f.tmp" fullword ascii
		$s1 = "%s\\1.txt" fullword ascii
		$s2 = "%windows%" fullword ascii
		$s3 = "%s\\system32" fullword ascii
		$s4 = "\\Help\\SYSTEM32\\" ascii
		$s5 = "%windows%\\mfc42l00.pdb" ascii
		$s6 = "Size of log(%dB) is too big, stop write." fullword ascii
		$s7 = "Log: Size of log(%dB) is too big, stop write." fullword ascii
		$s8 = "%02d.%02d.%04d Log begin:" fullword ascii
		$s9 = "\\system32\\win.com" ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (1 of ($x*) or 4 of them )
}