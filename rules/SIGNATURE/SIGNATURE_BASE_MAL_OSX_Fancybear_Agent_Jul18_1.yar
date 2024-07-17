rule SIGNATURE_BASE_MAL_OSX_Fancybear_Agent_Jul18_1 : FILE
{
	meta:
		description = "Detects FancyBear Agent for OSX"
		author = "Florian Roth (Nextron Systems)"
		id = "ae717f70-7196-561a-916f-1598ab38c77a"
		date = "2018-07-15"
		modified = "2023-12-05"
		reference = "https://twitter.com/DrunkBinary/status/1018448895054098432"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_fancybear_osxagent.yar#L1-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "099235424f22f3591a891726ea0c13ebf831fae0456ab1b6baba329c090a9535"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d3be93f6ce59b522ff951cef9d59ef347081ffe33d4203cd5b5df0aaa9721aa2"

	strings:
		$x1 = "/Users/kazak/Desktop/" ascii
		$s1 = "launchctl load -w ~/Library/LaunchAgents/com.apple.updates.plist" fullword ascii
		$s2 = "mkdir -p /Users/Shared/.local/ &> /dev/null" fullword ascii
		$s3 = "chmod 755 /Users/Shared/start.sh" fullword ascii
		$s4 = "chmod 755 %s/%s &> /dev/null" fullword ascii
		$s6 = "chmod 755 /Users/Shared/.local/kextd" fullword ascii

	condition:
		uint16(0)==0xfacf and filesize <3000KB and (1 of ($x*) and 4 of them )
}