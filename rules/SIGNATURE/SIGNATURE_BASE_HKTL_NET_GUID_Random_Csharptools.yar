import "pe"


rule SIGNATURE_BASE_HKTL_NET_GUID_Random_Csharptools : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "ad8b5573-ad20-50cd-927b-a6401b10e653"
		date = "2020-12-21"
		modified = "2023-04-06"
		reference = "https://github.com/xorrior/Random-CSharpTools"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2781-L2807"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "d1d5e372c6e1314ebf317b51633b83b2f9336048cc223982052e078ca86ee6bc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "f7fc19da-67a3-437d-b3b0-2a257f77a00b" ascii wide
		$typelibguid0up = "F7FC19DA-67A3-437D-B3B0-2A257F77A00B" ascii wide
		$typelibguid1lo = "47e85bb6-9138-4374-8092-0aeb301fe64b" ascii wide
		$typelibguid1up = "47E85BB6-9138-4374-8092-0AEB301FE64B" ascii wide
		$typelibguid2lo = "c7d854d8-4e3a-43a6-872f-e0710e5943f7" ascii wide
		$typelibguid2up = "C7D854D8-4E3A-43A6-872F-E0710E5943F7" ascii wide
		$typelibguid3lo = "d6685430-8d8d-4e2e-b202-de14efa25211" ascii wide
		$typelibguid3up = "D6685430-8D8D-4E2E-B202-DE14EFA25211" ascii wide
		$typelibguid4lo = "1df925fc-9a89-4170-b763-1c735430b7d0" ascii wide
		$typelibguid4up = "1DF925FC-9A89-4170-B763-1C735430B7D0" ascii wide
		$typelibguid5lo = "817cc61b-8471-4c1e-b5d6-c754fc550a03" ascii wide
		$typelibguid5up = "817CC61B-8471-4C1E-B5D6-C754FC550A03" ascii wide
		$typelibguid6lo = "60116613-c74e-41b9-b80e-35e02f25891e" ascii wide
		$typelibguid6up = "60116613-C74E-41B9-B80E-35E02F25891E" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}