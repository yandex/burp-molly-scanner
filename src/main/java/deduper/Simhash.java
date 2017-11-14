/**
 * 
 */
package deduper;

import java.util.List;

/**
 * @author zhangcheng
 * 
 */
public class Simhash {

	private IWordSeg wordSeg;

	public Simhash(IWordSeg wordSeg) {
		this.wordSeg = wordSeg;
	}

	public long simhash64(String doc) {
		int bitLen = 64;
		int[] bits = new int[bitLen];
		List<String> tokens = wordSeg.tokens(doc);
		for (String t : tokens) {
			long v = MurmurHash.hash64(t);
			for (int i = bitLen; i >= 1; --i) {
				if (((v >> (bitLen - i)) & 1) == 1)
					++bits[i - 1];
				else
					--bits[i - 1];
			}
		}
		long hash = 0x0000000000000000;
		long one = 0x0000000000000001;
		for (int i = bitLen; i >= 1; --i) {
			if (bits[i - 1] > 1) {
				hash |= one;
			}
			one = one << 1;
		}
		return hash;
	}

	public long simhash32(String doc) {
		int bitLen = 32;
		int[] bits = new int[bitLen];
		List<String> tokens = wordSeg.tokens(doc);
		for (String t : tokens) {
			int v = MurmurHash.hash32(t);
			for (int i = bitLen; i >= 1; --i) {
				if (((v >> (bitLen - i)) & 1) == 1)
					++bits[i - 1];
				else
					--bits[i - 1];
			}
		}
		int hash = 0x00000000;
		int one = 0x00000001;
		for (int i = bitLen; i >= 1; --i) {
			if (bits[i - 1] > 1) {
				hash |= one;
			}
			one = one << 1;
		}
		return hash;
	}
}
