rule ESET_Apt_Windows_TA410_Flowcloud_V5_Resources : FILE
{
	meta:
		description = "Matches sequence of PE resource IDs found in TA410 FlowCloud version 5.0.2"
		author = "ESET Research"
		id = "05a233f0-a823-5154-a47d-cede722d4710"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/ta410/ta410.yar#L699-L720"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "58f75dda53c6d4b3d88f464c452d855ac6dc88add5f4fba2641f52e7a1ae00ed"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	condition:
		uint16(0)==0x5a4d and pe.number_of_resources>=13 and for 12resource in pe.resources : (resource.type==10 and resource.language==1033 and (resource.name_string=="1\x000\x000\x00" or resource.name_string=="1\x000\x000\x000\x00" or resource.name_string=="1\x000\x000\x000\x000\x00" or resource.name_string=="1\x000\x000\x001\x00" or resource.name_string=="1\x000\x001\x00" or resource.name_string=="1\x000\x002\x00" or resource.name_string=="1\x000\x003\x00" or resource.name_string=="1\x000\x004\x00" or resource.name_string=="1\x000\x005\x00" or resource.name_string=="1\x000\x006\x00" or resource.name_string=="1\x000\x007\x00" or resource.name_string=="1\x000\x008\x00" or resource.name_string=="1\x000\x009\x00" or resource.name_string=="1\x001\x000\x00" or resource.name_string=="2\x000\x000\x000\x00" or resource.name_string=="2\x000\x000\x001\x00"))
}