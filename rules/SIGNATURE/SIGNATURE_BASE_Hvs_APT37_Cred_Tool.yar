import "pe"


rule SIGNATURE_BASE_Hvs_APT37_Cred_Tool : FILE
{
	meta:
		description = "Unknown cred tool used by APT37"
		author = "Markus Poelloth"
		id = "e830025a-f2ac-55b1-aca3-ded9dba83a67"
		date = "2020-12-15"
		modified = "2023-12-05"
		reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lazarus_dec20.yar#L31-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "4fb7247b88f2d252e7c9d5034c209945bc9e17f49de3dcdb5bf50b5afb302987"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
		$s2 = "Domain Login" fullword ascii
		$s3 = "IEShims_GetOriginatingThreadContext" fullword ascii
		$s4 = " Type Descriptor'" fullword ascii
		$s5 = "User: %s" fullword ascii
		$s6 = "Pass: %s" fullword ascii
		$s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
		$s8 = "E@c:\\u" fullword ascii

	condition:
		filesize <500KB and 7 of them
}