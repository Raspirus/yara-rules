import "pe"


rule SIGNATURE_BASE_APT_APT41_HIGHNOON_2 : FILE
{
	meta:
		description = "Detects APT41 malware HIGHNOON"
		author = "Florian Roth (Nextron Systems)"
		id = "1e48d859-2da9-583e-80e5-8d59054cfb85"
		date = "2019-08-07"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_apt41.yar#L137-L157"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "dc35b78df1631b1c9650de2bac625a7bc629225f36fe5e32fbff829cb77dc9ac"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d"

	strings:
		$x1 = "H:\\RBDoor\\" ascii
		$s1 = "PlusDll.dll" fullword ascii
		$s2 = "ShutDownEvent.dll" fullword ascii
		$s3 = "\\svchost.exe" ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="b70358b00dd0138566ac940d0da26a03" or pe.exports("DllMain_mem") or $x1 or 3 of them )
}