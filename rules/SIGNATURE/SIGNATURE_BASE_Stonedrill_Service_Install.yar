import "pe"

import "math"


rule SIGNATURE_BASE_Stonedrill_Service_Install : FILE
{
	meta:
		description = "Rule to detect Batch file from StoneDrill report"
		author = "Florian Roth (Nextron Systems)"
		id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_stonedrill.yar#L82-L96"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "52abe90c7f87ffeace4b58f9959e5a21c475bfa7ae2c5bc2744fe5fe43ffdda8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "127.0.0.1 >nul && sc config" ascii
		$s2 = "LocalService\" && ping -n" ascii fullword
		$s3 = "127.0.0.1 >nul && sc start" ascii fullword
		$s4 = "sc config NtsSrv binpath= \"C:\\WINDOWS\\system32\ntssrvr64.exe" ascii

	condition:
		2 of them and filesize <500
}