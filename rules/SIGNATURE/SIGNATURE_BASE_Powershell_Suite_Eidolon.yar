
rule SIGNATURE_BASE_Powershell_Suite_Eidolon : FILE
{
	meta:
		description = "Detects PowerShell Suite Eidolon script - file Start-Eidolon.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "5440d8fc-b939-556f-a8a0-ef5feb29e32f"
		date = "2017-12-27"
		modified = "2023-12-05"
		reference = "https://github.com/FuzzySecurity/PowerShell-Suite"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_powershell_suite.yar#L48-L63"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "587a9a8569801e2aa96a6f171705fdc1db5632734b54e5a9eb8282502e1efc63"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "db31367410d0a9ffc9ed37f423a4b082639591be7f46aca91f5be261b23212d5"

	strings:
		$ = "[+] Eidolon entry point:" ascii
		$ = "C:\\PS> Start-Eidolon -Target C:\\Some\\File.Path -Mimikatz -Verbose" fullword ascii
		$ = "[Int16]$PEArch = '0x{0}' -f ((($PayloadBytes[($OptOffset+1)..($OptOffset)]) | % {$_.ToString('X2')}) -join '')" fullword ascii

	condition:
		uint16(0)==0x7566 and filesize <13000KB and 1 of them
}