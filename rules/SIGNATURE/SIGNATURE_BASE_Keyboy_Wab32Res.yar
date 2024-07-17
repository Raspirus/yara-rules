import "pe"


rule SIGNATURE_BASE_Keyboy_Wab32Res : FILE
{
	meta:
		description = "Detects KeyBoy Loader wab32res.dll"
		author = "Markus Neis, Florian Roth"
		id = "0e4045a7-1c45-5043-9e10-e969219b67f8"
		date = "2018-03-26"
		modified = "2023-12-05"
		reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/tropic-trooper-new-strategy/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_keyboys.yar#L75-L96"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5e23bfeed0587ac69527234dd3f8b4f8c5628128ab667af7b99c4d75ca99459b"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "02281e26e89b61d84e2df66a0eeb729c5babd94607b1422505cd388843dd5456"
		hash2 = "fb9c9cbf6925de8c7b6ce8e7a8d5290e628be0b82a58f3e968426c0f734f38f6"

	strings:
		$x1 = "B4490-2314-55C1- /Processid:{321bitsadmin /canceft\\windows\\curresoftware\\microso" fullword ascii
		$x2 = "D:\\Work\\VS\\House\\TSSL\\TSSL\\TClient" ascii
		$x3 = "\\Release\\FakeRun.pdb" ascii
		$x4 = "FakeRun.dll" fullword ascii
		$s1 = "cmd.exe /c \"%s\"" fullword ascii
		$s2 = "CreateProcess failed (%d)" fullword ascii
		$s3 = "CreateProcess %s " fullword ascii
		$s4 = "FindResource %s error " fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and (1 of ($x*) or 4 of them )
}