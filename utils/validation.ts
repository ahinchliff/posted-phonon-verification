import { utils, verify } from '@noble/secp256k1';
import { TransferPacket } from '../types';

export const isSenderCertificateValid = async (
	packet: TransferPacket,
	certAuthorityPublicKey: Uint8Array | string,
): Promise<boolean> => {
	const { senderCert } = packet;

	const sigData = Uint8Array.of(
		senderCert.permissions.permType,
		senderCert.permissions.permLen,
		...senderCert.permissions.permissions,
		senderCert.permissions.pubKeyType,
		senderCert.permissions.pubKeyLen,
		...senderCert.publicKey,
	);

	const sigDataHash = await utils.sha256(sigData);
	return verify(senderCert.signature, sigDataHash, certAuthorityPublicKey, {
		strict: false,
	});
};

export const isSignatureValid = async (
	packet: TransferPacket,
): Promise<boolean> => {
	const { nonce, senderCert, recipientPublicKey, phonons } = packet;
	// sig := append(recipientsPublicKey, nonce...)
	// return append(sig, phonons...)
	const sigData = Uint8Array.of(...recipientPublicKey, ...nonce, ...phonons);
	const sigDataHash = await utils.sha256(sigData);
	return verify(senderCert.signature, sigDataHash, packet.senderCert.publicKey, {
		strict: false,
	});
};
