rule SIGNATURE_BASE_APT_MAL_LNX_Kobalos_SSH_Credential_Stealer : FILE
{
	meta:
		description = "Kobalos SSH credential stealer seen in OpenSSH client"
		author = "Marc-Etienne M.Leveille"
		id = "0f923f92-c5d8-500d-9a2e-634ca7945c5c"
		date = "2020-11-02"
		modified = "2023-12-05"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_lnx_kobalos.yar#L59-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "fdabaea0c838e43b8716bcd102bdeebf2f08fc041b0b909333e3d9d6f94391fc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$ = "user: %.128s host: %.128s port %05d user: %.128s password: %.128s"

	condition:
		uint16(0)==0x457f and any of them
}