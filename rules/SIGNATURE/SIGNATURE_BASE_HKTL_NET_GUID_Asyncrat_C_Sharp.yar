rule SIGNATURE_BASE_HKTL_NET_GUID_Asyncrat_C_Sharp : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "858a079d-71e8-516e-a2a9-f0969edc758b"
		date = "2020-12-13"
		modified = "2023-04-06"
		reference = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L2387-L2421"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "efb1c38e502483c25f8b81d6485f11130ed91a31a4dc64486db5c8bf2e8b1a53"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "619b7612-dfea-442a-a927-d997f99c497b" ascii wide
		$typelibguid0up = "619B7612-DFEA-442A-A927-D997F99C497B" ascii wide
		$typelibguid1lo = "424b81be-2fac-419f-b4bc-00ccbe38491f" ascii wide
		$typelibguid1up = "424B81BE-2FAC-419F-B4BC-00CCBE38491F" ascii wide
		$typelibguid2lo = "37e20baf-3577-4cd9-bb39-18675854e255" ascii wide
		$typelibguid2up = "37E20BAF-3577-4CD9-BB39-18675854E255" ascii wide
		$typelibguid3lo = "dafe686a-461b-402b-bbd7-2a2f4c87c773" ascii wide
		$typelibguid3up = "DAFE686A-461B-402B-BBD7-2A2F4C87C773" ascii wide
		$typelibguid4lo = "ee03faa9-c9e8-4766-bd4e-5cd54c7f13d3" ascii wide
		$typelibguid4up = "EE03FAA9-C9E8-4766-BD4E-5CD54C7F13D3" ascii wide
		$typelibguid5lo = "8bfc8ed2-71cc-49dc-9020-2c8199bc27b6" ascii wide
		$typelibguid5up = "8BFC8ED2-71CC-49DC-9020-2C8199BC27B6" ascii wide
		$typelibguid6lo = "d640c36b-2c66-449b-a145-eb98322a67c8" ascii wide
		$typelibguid6up = "D640C36B-2C66-449B-A145-EB98322A67C8" ascii wide
		$typelibguid7lo = "8de42da3-be99-4e7e-a3d2-3f65e7c1abce" ascii wide
		$typelibguid7up = "8DE42DA3-BE99-4E7E-A3D2-3F65E7C1ABCE" ascii wide
		$typelibguid8lo = "bee88186-769a-452c-9dd9-d0e0815d92bf" ascii wide
		$typelibguid8up = "BEE88186-769A-452C-9DD9-D0E0815D92BF" ascii wide
		$typelibguid9lo = "9042b543-13d1-42b3-a5b6-5cc9ad55e150" ascii wide
		$typelibguid9up = "9042B543-13D1-42B3-A5B6-5CC9AD55E150" ascii wide
		$typelibguid10lo = "6aa4e392-aaaf-4408-b550-85863dd4baaf" ascii wide
		$typelibguid10up = "6AA4E392-AAAF-4408-B550-85863DD4BAAF" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}