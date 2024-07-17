rule SIGNATURE_BASE_Invoke_Metasploit : FILE
{
	meta:
		description = "Detects Invoke-Metasploit Payload"
		author = "Florian Roth (Nextron Systems)"
		id = "40452884-df3f-5b49-ad10-05006cb115f2"
		date = "2017-09-23"
		modified = "2023-12-05"
		reference = "https://github.com/jaredhaight/Invoke-MetasploitPayload/blob/master/Invoke-MetasploitPayload.ps1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/thor-hacktools.yar#L4071-L4086"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "7ef174008517b101be844e30890626378f49a275bad3f08ce25fb8d6118c77c3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b36d3ca7073741c8a48c578edaa6d3b6a8c3c4413e961a83ad08ad128b843e0b"

	strings:
		$s1 = "[*] Looks like we're 64bit, using regular powershell.exe" ascii wide
		$s2 = "[*] Kicking off download cradle in a new process"
		$s3 = "Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;Invoke-Expression $client.downloadstring('''+$url+''');'"

	condition:
		( filesize <20KB and 1 of them )
}