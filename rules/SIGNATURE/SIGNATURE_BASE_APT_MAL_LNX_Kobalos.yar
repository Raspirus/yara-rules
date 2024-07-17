
rule SIGNATURE_BASE_APT_MAL_LNX_Kobalos : FILE
{
	meta:
		description = "Kobalos malware"
		author = "Marc-Etienne M.Leveille"
		id = "dfa47e30-c093-57f6-af01-72a2534cc6f4"
		date = "2020-11-02"
		modified = "2023-12-05"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lnx_kobalos.yar#L32-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "48aec47b70633d4c8cb55d90a2e168f3c2027ef27cfe1cd5d30dcdc08a2ff717"
		score = 75
		quality = 85
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$encrypted_strings_sizes = {
            05 00 00 00 09 00 00 00  04 00 00 00 06 00 00 00
            08 00 00 00 08 00 00 00  02 00 00 00 02 00 00 00
            01 00 00 00 01 00 00 00  05 00 00 00 07 00 00 00
            05 00 00 00 05 00 00 00  05 00 00 00 0A 00 00 00
        }
		$password_md5_digest = { 3ADD48192654BD558A4A4CED9C255C4C }
		$rsa_512_mod_header = { 10 11 02 00 09 02 00 }
		$strings_rc4_key = { AE0E05090F3AC2B50B1BC6E91D2FE3CE }

	condition:
		uint16(0)==0x457f and any of them
}