
rule SIGNATURE_BASE_Badrabbit_Gen : FILE
{
	meta:
		description = "Detects BadRabbit Ransomware"
		author = "Florian Roth (Nextron Systems)"
		id = "272e50f8-5aef-52ec-a5d0-01e8504d6c55"
		date = "2017-10-25"
		modified = "2023-12-05"
		reference = "https://pastebin.com/Y7pJv3tK"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_badrabbit.yar#L11-L40"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "21c63a02d0284ce759b087f4869c4ed8e6b50c37ffeb724538567e28aeae16ac"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8ebc97e05c8e1073bda2efb6f4d00ad7e789260afa2c276f0c72740b838a0a93"
		hash2 = "579fd8a0385482fb4c789561a30b09f25671e86422f40ef5cca2036b28f99648"
		hash3 = "630325cac09ac3fab908f903e3b00d0dadd5fdaa0875ed8496fcbb97a558d0da"

	strings:
		$x1 = "schtasks /Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR \"%ws\" /ST" fullword wide
		$x2 = "schtasks /Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR \"%ws /C Start \\\"\\\" \\\"%wsdispci.exe\\\"" fullword wide
		$x3 = "C:\\Windows\\infpub.dat" fullword wide
		$x4 = "C:\\Windows\\cscc.dat" fullword wide
		$s1 = "need to do is submit the payment and get the decryption password." fullword ascii
		$s2 = "\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)" fullword wide
		$s3 = "\\\\.\\pipe\\%ws" fullword wide
		$s4 = "fsutil usn deletejournal /D %c:" fullword wide
		$s5 = "Run DECRYPT app at your desktop after system boot" fullword ascii
		$s6 = "Files decryption completed" fullword wide
		$s7 = "Disable your anti-virus and anti-malware programs" fullword wide
		$s8 = "SYSTEM\\CurrentControlSet\\services\\%ws" fullword wide
		$s9 = "process call create \"C:\\Windows\\System32\\rundll32.exe" fullword wide
		$s10 = "%ws C:\\Windows\\%ws,#1 %ws" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <700KB and (1 of ($x*) or 2 of them )
}