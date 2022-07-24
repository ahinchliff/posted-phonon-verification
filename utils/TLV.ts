type TLV = {
	tag: number;
	value: Uint8Array;
};

export default class TLVCollection {
	public tlvs: TLV[];

	constructor(bytes: Uint8Array) {
		let index = 0;
		const results: TLV[] = [];
		while (index < bytes.length) {
			const tag = bytes[index];
			const length = bytes[index + 1];
			const dataEndingIndex = index + 2 + length;
			const value = bytes.slice(index + 2, dataEndingIndex);
			results.push({ tag, value });
			index = dataEndingIndex;
		}
		this.tlvs = results;
	}

	public getValues = (tag: number): Uint8Array[] =>
		this.tlvs.filter((tlv) => tlv.tag === tag).map((tvl) => tvl.value);

	public getValue = (tag: number): Uint8Array => {
		const value = this.getValues(tag)[0];
		if (!value) {
			throw new Error(`No tag found: ${tag}`);
		}
		return value;
	};
}
