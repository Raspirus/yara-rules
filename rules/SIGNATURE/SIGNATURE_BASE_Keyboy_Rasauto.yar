rule SIGNATURE_BASE_Keyboy_Rasauto : FILE
{
	meta:
		description = "Detects KeyBoy ServiceClient"
		author = "Markus Neis, Florian Roth"
		id = "b6c72a91-fda1-5f40-804f-896b25a8813f"
		date = "2018-03-26"
		modified = "2023-12-05"
		reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/tropic-trooper-new-strategy/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_keyboys.yar#L98-L126"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "87529000522d5fad4346a0228c96d3adf122587d91b0cff083948787e53cc024"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "49df4fec76a0ffaee5e4d933a734126c1a7b32d1c9cb5ab22a868e8bfc653245"

	strings:
		$x1 = "rundll32.exe %s SSSS & exit" fullword ascii
		$x2 = "D:\\Work\\Project\\VS\\HSSL\\HSSL_Unicode _2\\Release\\ServiceClient.pdb" fullword ascii
		$s1 = "cmd.exe /c \"%s\"" fullword ascii
		$s2 = "CreateProcess failed (%d)" fullword ascii
		$s3 = "ServiceClient.dll" fullword ascii
		$s4 = "NtWow64QueryInformationProcess64 failed" fullword ascii
		$s5 = "pid:%d CmdLine:%S" fullword ascii
		$s6 = "rasauto32.ServiceMain" fullword ascii
		$s7 = "del /q/f %s\\%s*" fullword ascii
		$s8 = "szTmpDll:%s" fullword ascii
		$s9 = "lpCmdLine:%s" fullword ascii
		$s0 = "ReleaseFileFromRes:%s ok!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (pe.exports("SSSS") or 1 of ($x*) or 4 of them )
}