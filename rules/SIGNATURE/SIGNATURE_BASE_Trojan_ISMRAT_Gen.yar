rule SIGNATURE_BASE_Trojan_ISMRAT_Gen : FILE
{
	meta:
		description = "ISM RAT"
		author = "Ahmed Zaki"
		id = "e72241ce-d6ee-5cb7-a83d-157161938d83"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/february/ism-rat/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_ism_rat.yar#L9-L25"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "c4d26f79b8110e92a5e427de303eca6eaf79765a4c9cc437864dc5160ef2e343"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "146a112cb01cd4b8e06d36304f6bdf7b"
		hash2 = "fa3dbe37108b752c38bf5870b5862ce5"
		hash3 = "bf4b07c7b4a4504c4192bd68476d63b5"

	strings:
		$s1 = "WinHTTP Example/1.0" wide
		$s2 = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0" wide
		$s3 = "|||Command executed successfully"
		$dir = /Microsoft\\Windows\\Tmpe[a-z0-9]{2,8}/

	condition:
		uint16(0)==0x5A4D and all of them
}