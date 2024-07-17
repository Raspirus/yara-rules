rule SIGNATURE_BASE_MAL_Ransomware_Win_DARKSIDE_V1_1 : FILE
{
	meta:
		description = "Detection for early versions of DARKSIDE ransomware samples based on the encryption mode configuration values."
		author = "FireEye"
		id = "322a3de5-a7e5-52b9-8648-6019954e92d7"
		date = "2021-03-22"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_ransom_darkside.yar#L25-L37"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "1a700f845849e573ab3148daef1a3b0b"
		logic_hash = "b3612510bd1f2ca7543e217e97037b02d312bcda2b2df16d9be3216749ea4beb"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$consts = { 80 3D [4] 01 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] 00 00 04 00 [1-10] 00 00 00 00 [1-30] 80 3D [4] 02 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] FF FF FF FF [1-10] FF FF FF FF [1-30] 03 00 00 00 [1-10] 03 00 00 00 }

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $consts
}