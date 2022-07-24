import { CardCertificate, TransferPacket } from '../types';
import TLVCollection from './TLV';

const TAG_TRANSFER_PACKET = 67;
const TAG_SIGNATURE = 147;
const TAG_SENDER_CERT = 144;
const TAG_NONCE = 151;
const TAG_RECIPIENT_PUBLIC_KEY = 152;

export const parsePacket = (packet: string): TransferPacket => {
	const tlv = new TLVCollection(hexToBytes(packet));

	const nonce = tlv.getValue(TAG_NONCE);
	const recipientPublicKey = tlv.getValue(TAG_RECIPIENT_PUBLIC_KEY);
	const senderCert = tlv.getValue(TAG_SENDER_CERT);
	const phonons = tlv.getValue(TAG_TRANSFER_PACKET);
	const signature = tlv.getValue(TAG_SIGNATURE);

	return {
		nonce,
		recipientPublicKey,
		senderCert: parseCert(senderCert),
		phonons,
		signature,
	};
};

const parseCert = (bytes: Uint8Array): CardCertificate => {
	const certType = bytes[0];
	const certLen = bytes[1];
	const permType = bytes[2];
	const permLen = bytes[3];
	const permissions = bytes.slice(4, 4 + permLen);
	const pubKeyType = bytes[4 + permLen];
	const pubKeyLen = bytes[5 + permLen];
	const publicKey = bytes.slice(6 + permLen, 6 + permLen + pubKeyLen);
	const signature = bytes.slice(6 + permLen + pubKeyLen, certLen);

	return {
		permissions: {
			certType,
			certLen,
			permType,
			permLen,
			pubKeyType,
			pubKeyLen,
			permissions,
		},
		publicKey,
		signature,
	};
};

const hexToBytes = (hex: string): Uint8Array => {
	for (var bytes = [], c = 0; c < hex.length; c += 2)
		bytes.push(parseInt(hex.substr(c, 2), 16));
	return Uint8Array.from(bytes);
};
