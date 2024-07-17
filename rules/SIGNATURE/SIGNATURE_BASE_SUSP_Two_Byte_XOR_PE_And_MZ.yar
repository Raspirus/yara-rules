rule SIGNATURE_BASE_SUSP_Two_Byte_XOR_PE_And_MZ : FILE
{
	meta:
		description = "Look for 2 byte xor of a PE starting at offset 0"
		author = "Wesley Shields <wxs@atarininja.org>"
		id = "ddb87194-bafb-597d-9184-fe4fe3c5ce8d"
		date = "2021-10-11"
		modified = "2023-12-05"
		reference = "https://gist.github.com/wxsBSD/bf7b88b27e9f879016b5ce2c778d3e83"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_xored_pe.yar#L2-L13"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8a43ff9ec966df72ef35fb9ba9bbbd6f8b0f3761669bb91dc5919645d6327174"
		score = 70
		quality = 85
		tags = "FILE"

	condition:
		uint16(0)!=0x5a4d and uint32(( uint16(0x3c)^( uint16(0)^0x5a4d))|(( uint16(0x3e)^( uint16(0)^0x5a4d))<<16))^(( uint16(0)^0x5a4d)|(( uint16(0)^0x5a4d)<<16))==0x00004550
}