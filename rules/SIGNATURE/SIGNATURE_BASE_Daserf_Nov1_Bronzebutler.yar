rule SIGNATURE_BASE_Daserf_Nov1_Bronzebutler : FILE
{
	meta:
		description = "Detects Daserf malware used by Bronze Butler"
		author = "Florian Roth (Nextron Systems)"
		id = "58c4d3dc-c516-567b-8746-4e185c3cd328"
		date = "2017-11-08"
		modified = "2023-12-05"
		reference = "https://goo.gl/ffeCfd"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_bronze_butler.yar#L170-L196"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "75edc17c51f4ea82ff7722df2f5825721ff64445fb8c78b450f1333bd32b5829"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5ede6f93f26ccd6de2f93c9bd0f834279df5f5cfe3457915fae24a3aec46961b"

	strings:
		$x1 = "mstmp1845234.exe" fullword ascii
		$x2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; SV1)" fullword ascii
		$x3 = "Mozilla/4.0 (compatible; MSIE 11.0; Windows NT 6.1; SV1)" fullword ascii
		$s1 = "Content-Type: */*" fullword ascii
		$s2 = "ProxyEnable" ascii fullword
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii fullword
		$s4 = "iexplore.exe" ascii fullword
		$s5 = "\\SOFTWARE\\Microsoft\\Windows\\Cu" ascii
		$s6 = "rrentVersion\\Internet Settings" fullword ascii
		$s7 = "ws\\CurrentVersion\\Inter" fullword ascii
		$s8 = "Documents an" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and (1 of ($x*) or 5 of them )
}