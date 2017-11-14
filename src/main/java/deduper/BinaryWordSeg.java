/**
 * 
 */
package deduper;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * @author zhangcheng
 *
 */
public class BinaryWordSeg implements IWordSeg {

	@Override
	public List<String> tokens(String doc) {
		List<String> binaryWords = new LinkedList<String>();
		for(int i = 0; i < doc.length() - 1; i += 1) {
			StringBuilder bui = new StringBuilder();
			bui.append(doc.charAt(i)).append(doc.charAt(i + 1));
			binaryWords.add(bui.toString());
		}
		return binaryWords;
	}

	@Override
	public List<String> tokens(String doc, Set<String> stopWords) {
		return null;
	}

}
