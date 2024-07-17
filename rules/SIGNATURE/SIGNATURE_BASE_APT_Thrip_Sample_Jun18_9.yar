import "pe"


rule SIGNATURE_BASE_APT_Thrip_Sample_Jun18_9 : FILE
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		author = "Florian Roth (Nextron Systems)"
		id = "7fcd8d7f-ed60-5155-a0dd-f3a36f3f2981"
		date = "2018-06-21"
		modified = "2023-12-05"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_thrip.yar#L150-L170"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "0500481ae4bb7d4a223a106d2887b994e5000815704e678b2f3ff127a86c22a2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8e6682bcc51643f02a864b042f7223b157823f3d890fe21d38caeb43500d923e"
		hash2 = "0c8ca0fd0ec246ef207b96a3aac5e94c9c368504905b0a033f11eef8c62fa14c"
		hash3 = "6d0a2c822e2bc37cc0cec35f040d3fec5090ef2775df658d3823e47a93a5fef3"
		hash4 = "0c49d1632eb407b5fd0ce32ed45b1c783ac2ef60d001853ae1f6b7574e08cfa9"

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (pe.imphash()=="a7f0714e82b3105031fa7bc89dfe7664" or pe.imphash()=="8812ff21aeb160e8800257140acae54b" or pe.imphash()=="44a1e904763fe2d0837c747c7061b010" or pe.imphash()=="51a854d285aa12eb82e76e6e1be01573" or pe.imphash()=="a1f457c8c549c5c430556bfe5887a4e6")
}