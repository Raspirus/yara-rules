import "pe"


rule SIGNATURE_BASE_MAL_Burningumbrella_Sample_15 : FILE
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		author = "Florian Roth (Nextron Systems)"
		id = "4dc840c1-e6fa-5b21-bfcd-ef07cd85272a"
		date = "2018-05-04"
		modified = "2023-12-05"
		reference = "https://401trg.pw/burning-umbrella/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_winnti_burning_umbrella.yar#L233-L248"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "8541231fe1e48d7130aed64eee964f8eda6792b5dd3e708b98e9cc6f1f620cd0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "be6bea22e909bd772d21647ffee6d15e208e386e8c3c95fd22816c6b94196ae8"
		hash2 = "72a8fa454f428587d210cba0e74735381cd0332f3bdcbb45eecb7e271e138501"
		hash3 = "9cc38ea106efd5c8e98c2e8faf97c818171c52fa3afa0c4c8f376430fa556066"
		hash4 = "1a4a64f01b101c16e8b5928b52231211e744e695f125e056ef7a9412da04bb91"
		hash5 = "3cd42e665e21ed4815af6f983452cbe7a4f2ac99f9ea71af4480a9ebff5aa048"

	condition:
		uint16(0)==0x5a4d and filesize <50KB and pe.imphash()=="cc33b1500354cf785409a3b428f7cd2a"
}