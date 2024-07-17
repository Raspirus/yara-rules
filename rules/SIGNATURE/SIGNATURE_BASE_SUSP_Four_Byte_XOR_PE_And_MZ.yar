
rule SIGNATURE_BASE_SUSP_Four_Byte_XOR_PE_And_MZ : FILE
{
	meta:
		description = "Look for 4 byte xor of a PE starting at offset 0"
		author = "Wesley Shields <wxs@atarininja.org>"
		id = "d7b4b462-dfde-5d1f-8039-63522436c15f"
		date = "2021-10-11"
		modified = "2023-12-05"
		reference = "https://gist.github.com/wxsBSD/bf7b88b27e9f879016b5ce2c778d3e83"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_xored_pe.yar#L15-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "28230cd3c1d1da97a98df09243593eb59b57f376f651d5f22c3ea5903f0f73e4"
		score = 70
		quality = 85
		tags = "FILE"

	condition:
		uint16(0)!=0x5a4d and uint32(0x28)!=0x00000000 and uint32(0x28)== uint32(0x2c) and uint32( uint32(0x3c)^ uint32(0x28))^ uint32(0x28)==0x00004550
}