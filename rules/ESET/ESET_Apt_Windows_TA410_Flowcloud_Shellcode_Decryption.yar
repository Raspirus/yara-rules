rule ESET_Apt_Windows_TA410_Flowcloud_Shellcode_Decryption : FILE
{
	meta:
		description = "Matches the decryption function used in TA410 FlowCloud self-decrypting DLL"
		author = "ESET Research"
		id = "8af7b2fa-be40-5ec8-8413-1c982a463a9a"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/ta410/ta410.yar#L569-L615"
		license_url = "https://github.com/eset/malware-ioc/blob/3d18f6fe36ff39eddc204258096d65263da89de0/LICENSE"
		logic_hash = "939ffe6a41c957aa5d6c012484b2deab49a5e71a4b7e203a41c180f872803921"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$chunk_1 = {
            33 D2
            8B 45 ??
            BB 6B 04 00 00
            F7 F3
            81 C2 A8 01 00 00
            81 E2 FF 00 00 00
            8B 7D ??
            33 C9
            EB ??
            30 14 39
            00 14 39
            41
            3B 4D ??
            72 ??
        }

	condition:
		uint16(0)==0x5a4d and all of them
}