rule SIGNATURE_BASE_APT_SUSP_NK_3CX_RC4_Key_Mar23_1 : FILE
{
	meta:
		description = "Detects RC4 key used in 3CX binaries known to be malicious"
		author = "Florian Roth (Nextron Systems)"
		id = "18ea2185-11a1-51ad-a51a-df9e6357bb58"
		date = "2023-03-29"
		modified = "2023-12-05"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_mal_3cx_compromise_mar23.yar#L100-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8324b537b149ad3816b12ae0f887f66a284a8e1ef4fe7cf51eb21d59c0f055b9"
		score = 70
		quality = 85
		tags = "FILE"
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983"
		hash3 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
		hash4 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"

	strings:
		$x1 = "3jB(2bsG#@c7"

	condition:
		( uint16(0)==0xcfd0 or uint16(0)==0x5a4d) and $x1
}