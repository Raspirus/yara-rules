rule SIGNATURE_BASE_HKTL_NET_GUID_Altman : FILE
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "21acc8af-9497-5842-90a9-7a9300585d5d"
		date = "2020-12-28"
		modified = "2023-04-06"
		reference = "https://github.com/keepwn/Altman"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_github_net_redteam_tools_guids.yar#L4098-L4146"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "5ef32e351094f26bdaa87043b9ff202c25c67e6cd13935c3eb1ab7b4420b867c"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$typelibguid0lo = "64cdcd2b-7356-4079-af78-e22210e66154" ascii wide
		$typelibguid0up = "64CDCD2B-7356-4079-AF78-E22210E66154" ascii wide
		$typelibguid1lo = "f1dee29d-ca98-46ea-9d13-93ae1fda96e1" ascii wide
		$typelibguid1up = "F1DEE29D-CA98-46EA-9D13-93AE1FDA96E1" ascii wide
		$typelibguid2lo = "33568320-56e8-4abb-83f8-548e8d6adac2" ascii wide
		$typelibguid2up = "33568320-56E8-4ABB-83F8-548E8D6ADAC2" ascii wide
		$typelibguid3lo = "470ec930-70a3-4d71-b4ff-860fcb900e85" ascii wide
		$typelibguid3up = "470EC930-70A3-4D71-B4FF-860FCB900E85" ascii wide
		$typelibguid4lo = "9514574d-6819-44f2-affa-6158ac1143b3" ascii wide
		$typelibguid4up = "9514574D-6819-44F2-AFFA-6158AC1143B3" ascii wide
		$typelibguid5lo = "0f3a9c4f-0b11-4373-a0a6-3a6de814e891" ascii wide
		$typelibguid5up = "0F3A9C4F-0B11-4373-A0A6-3A6DE814E891" ascii wide
		$typelibguid6lo = "9624b72e-9702-4d78-995b-164254328151" ascii wide
		$typelibguid6up = "9624B72E-9702-4D78-995B-164254328151" ascii wide
		$typelibguid7lo = "faae59a8-55fc-48b1-a9b5-b1759c9c1010" ascii wide
		$typelibguid7up = "FAAE59A8-55FC-48B1-A9B5-B1759C9C1010" ascii wide
		$typelibguid8lo = "37af4988-f6f2-4f0c-aa2b-5b24f7ed3bf3" ascii wide
		$typelibguid8up = "37AF4988-F6F2-4F0C-AA2B-5B24F7ED3BF3" ascii wide
		$typelibguid9lo = "c82aa2fe-3332-441f-965e-6b653e088abf" ascii wide
		$typelibguid9up = "C82AA2FE-3332-441F-965E-6B653E088ABF" ascii wide
		$typelibguid10lo = "6e531f6c-2c89-447f-8464-aaa96dbcdfff" ascii wide
		$typelibguid10up = "6E531F6C-2C89-447F-8464-AAA96DBCDFFF" ascii wide
		$typelibguid11lo = "231987a1-ea32-4087-8963-2322338f16f6" ascii wide
		$typelibguid11up = "231987A1-EA32-4087-8963-2322338F16F6" ascii wide
		$typelibguid12lo = "7da0d93a-a0ae-41a5-9389-42eff85bb064" ascii wide
		$typelibguid12up = "7DA0D93A-A0AE-41A5-9389-42EFF85BB064" ascii wide
		$typelibguid13lo = "a729f9cc-edc2-4785-9a7d-7b81bb12484c" ascii wide
		$typelibguid13up = "A729F9CC-EDC2-4785-9A7D-7B81BB12484C" ascii wide
		$typelibguid14lo = "55a1fd43-d23e-4d72-aadb-bbd1340a6913" ascii wide
		$typelibguid14up = "55A1FD43-D23E-4D72-AADB-BBD1340A6913" ascii wide
		$typelibguid15lo = "d43f240d-e7f5-43c5-9b51-d156dc7ea221" ascii wide
		$typelibguid15up = "D43F240D-E7F5-43C5-9B51-D156DC7EA221" ascii wide
		$typelibguid16lo = "c2e6c1a0-93b1-4bbc-98e6-8e2b3145db8e" ascii wide
		$typelibguid16up = "C2E6C1A0-93B1-4BBC-98E6-8E2B3145DB8E" ascii wide
		$typelibguid17lo = "714ae6f3-0d03-4023-b753-fed6a31d95c7" ascii wide
		$typelibguid17up = "714AE6F3-0D03-4023-B753-FED6A31D95C7" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}