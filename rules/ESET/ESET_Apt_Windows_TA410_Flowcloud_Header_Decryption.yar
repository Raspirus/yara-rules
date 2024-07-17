rule ESET_Apt_Windows_TA410_Flowcloud_Header_Decryption : FILE
{
	meta:
		description = "Matches the function used to decrypt resources headers in TA410 FlowCloud"
		author = "ESET Research"
		id = "403c1845-bc25-5a49-8553-8a0be18d6970"
		date = "2024-01-30"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/ta410/ta410.yar#L417-L496"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "74b6c42bf2de159b2b0a15637e6bd94069367e3000c887714d6e3b50aa3646be"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"

	strings:
		$chunk_1 = {
            8B 1E
            8B CF
            D3 CB
            8D 0C 28
            83 C7 06
            30 18
            8B 1E
            D3 CB
            8D 0C 02
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            30 58 ??
            8B 1E
            D3 CB
            8B 4C 24 ??
            03 C8
            83 C0 06
            30 58 ??
            8B 1E
            D3 CB
            30 58 ??
            83 FF 10
            72 ??
        }

	condition:
		uint16(0)==0x5a4d and all of them
}