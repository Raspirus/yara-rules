rule SIGNATURE_BASE_APT_Lazarus_RAT_Jun18_1 : FILE
{
	meta:
		description = "Detects Lazarus Group RAT"
		author = "Florian Roth (Nextron Systems)"
		id = "fd394d15-70c5-543a-a845-2058f296b5f8"
		date = "2018-06-01"
		modified = "2023-12-05"
		reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_jun18.yar#L34-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7260f766ffd1122319ca69a6c87b0baa98d5727929f2e063a5b2edb05a44d827"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c10363059c57c52501c01f85e3bb43533ccc639f0ea57f43bae5736a8e7a9bc8"
		hash2 = "e98991cdd9ddd30adf490673c67a4f8241993f26810da09b52d8748c6160a292"

	strings:
		$a1 = "www.marmarademo.com/include/extend.php" fullword ascii
		$a2 = "www.33cow.com/include/control.php" fullword ascii
		$a3 = "www.97nb.net/include/arc.sglistview.php" fullword ascii
		$c1 = "Content-Disposition: form-data; name=\"file1\"; filename=\"example.dat\"" fullword ascii
		$c2 = "Content-Disposition: form-data; name=\"file1\"; filename=\"pratice.pdf\"" fullword ascii
		$c3 = "Content-Disposition: form-data; name=\"file1\"; filename=\"happy.pdf\"" fullword ascii
		$c4 = "Content-Disposition: form-data; name=\"file1\"; filename=\"my.doc\"" fullword ascii
		$c5 = "Content-Disposition: form-data; name=\"board_id\"" fullword ascii
		$s1 = "Winhttp.dll" fullword ascii
		$s2 = "Wsock32.dll" fullword ascii
		$s3 = "WM*.tmp" fullword ascii
		$s4 = "FM*.tmp" fullword ascii
		$s5 = "Cache-Control: max-age=0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (1 of ($a*) or 2 of ($c*) or 4 of them )
}