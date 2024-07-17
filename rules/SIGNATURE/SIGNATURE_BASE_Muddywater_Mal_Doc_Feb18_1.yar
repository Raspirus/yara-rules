
rule SIGNATURE_BASE_Muddywater_Mal_Doc_Feb18_1 : FILE
{
	meta:
		description = "Detects malicious document used by MuddyWater"
		author = "Florian Roth (Nextron Systems)"
		id = "5f275ee8-c6a9-532b-bc82-b109195171da"
		date = "2018-02-26"
		modified = "2023-12-05"
		reference = "Internal Research - TI2T"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_muddywater.yar#L10-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "b675b004f86695821737b7fc05276c8350e44f5822ec458a74658f895ccf7082"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3d96811de7419a8c090a671d001a85f2b1875243e5b38e6f927d9877d0ff9b0c"

	strings:
		$x1 = "aWV4KFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVuaWNvZGUuR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmco" ascii
		$x2 = "U1FCdUFIWUFid0JyQUdVQUxRQkZBSGdBY0FCeUFHVUFjd0J6QUdrQWJ3QnVBQ0FBS"

	condition:
		uint16(0)==0xcfd0 and filesize <3000KB and 1 of them
}