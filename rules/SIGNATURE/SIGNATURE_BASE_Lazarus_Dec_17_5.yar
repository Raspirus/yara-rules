rule SIGNATURE_BASE_Lazarus_Dec_17_5 : FILE
{
	meta:
		description = "Detects Lazarus malware from incident in Dec 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "33bd8c08-123e-5a8e-b5dc-02af7291addc"
		date = "2017-12-20"
		modified = "2023-12-05"
		reference = "https://goo.gl/8U6fY2"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_dec17.yar#L69-L89"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "480ec19f7050d34713ed621ae9ec5d5463b1cc4710b473465cc78e533796d2e4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "db8163d054a35522d0dec35743cfd2c9872e0eb446467b573a79f84d61761471"

	strings:
		$x1 = "$ProID = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList" fullword ascii
		$x2 = "$respTxt = HttpRequestFunc_doprocess -szURI $szFullURL -szMethod $szMethod -contentData $contentData;" fullword ascii
		$x3 = "[String]$PS_PATH = \"C:\\\\Users\\\\Public\\\\Documents\\\\ProxyAutoUpdate.ps1\";" fullword ascii
		$x4 = "$cmdSchedule = 'schtasks /create /tn \"ProxyServerUpdater\"" ascii
		$x5 = "/tr \"powershell.exe -ep bypass -windowstyle hidden -file " ascii
		$x6 = "C:\\\\Users\\\\Public\\\\Documents\\\\tmp' + -join " ascii
		$x7 = "$cmdResult = cmd.exe /c $cmdInst | Out-String;" fullword ascii
		$x8 = "whoami /groups | findstr /c:\"S-1-5-32-544\"" fullword ascii

	condition:
		filesize <500KB and 1 of them
}