package deduper;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

/**
 * Created by ezaitov on 20.02.2017.
 */
public class HtmlSeg implements IWordSeg {

        @Override
        public List<String> tokens(String html) {
            Document document;

            try {
                document = Jsoup.parse(html);
            } catch (Exception e) {
                IWordSeg wordSeg = new BinaryWordSeg();
                return wordSeg.tokens(html);
            }

            Iterator<Element> iterator = document.body().select("*").iterator();
            List<String> binaryWords = new LinkedList<String>();

            while(iterator.hasNext()){
                Element e = iterator.next();
                binaryWords.add(e.tagName());
                if (e.hasAttr("class")) {
                    binaryWords.add(e.className());
                }
            }

            /* was not able to parse as doc a HTML - parse it as a string */
            if (binaryWords.size() == 0) {
                IWordSeg wordSeg = new BinaryWordSeg();
                return wordSeg.tokens(html);
            }

            return binaryWords;
        }

        @Override
        public List<String> tokens(String doc, Set<String> stopWords) {
            return null;
        }

}
