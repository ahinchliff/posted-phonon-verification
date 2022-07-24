export type CardCertificate = {
	permissions: {
		certType: number;
		certLen: number;
		permType: number;
		permLen: number;
		permissions: Uint8Array;
		pubKeyType: number;
		pubKeyLen: number;
	};
	publicKey: Uint8Array;
	signature: Uint8Array;
};

export type TransferPacket = {
	nonce: Uint8Array;
	recipientPublicKey: Uint8Array;
	senderCert: CardCertificate;
	signature: Uint8Array;
	phonons: Uint8Array;
};
