rule SIGNATURE_BASE_Zxshell_20171211_Chrsben : FILE
{
	meta:
		description = "Detects ZxShell variant surfaced in Dec 17"
		author = "Florian Roth (Nextron Systems)"
		id = "3bbfddb8-011a-52dd-b0c8-b35e6f740507"
		date = "2017-12-11"
		modified = "2023-12-05"
		reference = "https://goo.gl/snc85M"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_zxshell.yar#L115-L138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "361441404582b0eaca25954f7fe1a3a3b9fefd15cac78d61408bc50aeb78bb61"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "dd01e7a1c9b20d36ea2d961737780f2c0d56005c370e50247e38c5ca80dcaa4f"

	strings:
		$x1 = "ncProxyXll" fullword ascii
		$s1 = "Uniscribe.dll" fullword ascii
		$s2 = "GetModuleFileNameDll" fullword ascii
		$s4 = "$Hangzhou Shunwang Technology Co.,Ltd0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and (pe.imphash()=="de481441d675e9aca4f20bd8e16a5faa" or pe.exports("PerfectWorld") or pe.exports("ncProxyXll") or 1 of ($x*) or 2 of them )
}