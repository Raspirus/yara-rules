rule ESET_Apt_Windows_TA410_Flowcloud_Fcclient_Strings : FILE
{
	meta:
		description = "Strings found in fcClient/rescure.dat module."
		author = "ESET Research"
		id = "876bae0b-2612-559b-9ead-b633a3789663"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/ta410/ta410.yar#L617-L639"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "c05b7031a5aec1bcf29eca06c010c402edeb24a093a2043dbc21781dff22c7fe"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "df257bdd-847c-490e-9ef9-1d7dc883d3c0"
		$s2 = "\\{2AFF264E-B722-4359-8E0F-947B85594A9A}"
		$s3 = "Global\\{26C96B51-2B5D-4D7B-BED1-3DCA4848EDD1}" wide
		$s4 = "{804423C2-F490-4ac3-BFA5-13DEDE63A71A}" wide
		$s5 = "{A5124AF5-DF23-49bf-B0ED-A18ED3DEA027}" wide
		$s6 = "XXXModule_func.dll"
		$driver1 = "\\drivers\\hidmouse.sys" wide fullword
		$driver2 = "\\drivers\\hidusb.sys" wide fullword

	condition:
		uint16(0)==0x5a4d and ( any of ($s*) or all of ($driver*))
}