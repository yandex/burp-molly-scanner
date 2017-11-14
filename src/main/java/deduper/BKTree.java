package deduper;

import java.util.HashMap;

/**
 * This class in an implementation of a Burkhard-Keller tree in Java.
 * The BK-Tree is a tree structure to quickly finding close matches to
 * any defined object.
 *
 * The BK-Tree was first described in the paper:
 * "Some Approaches to Best-Match File Searching" by W. A. Burkhard and R. M. Keller
 * It is available in the ACM archives.
 *
 * Another good explanation can be found here:
 * http://blog.notdot.net/2007/4/Damn-Cool-Algorithms-Part-1-BK-Trees
 *
 * Searching the tree yields O(logn), which is a huge upgrade over brute force
 *
 * @author Josh Clemm
 *
 */
public class BKTree <E> {

    private Node root;
    private HashMap<E, Integer> matches;
    private Distance distance;
    private E bestTerm;

    public BKTree(Distance distance) {
        root = null;
        this.distance = distance;
    }

    public void add(E term) {
        if(root != null) {
            root.add(term);
        }
        else {
            root = new Node(term);
        }
    }

    public boolean isEmpty() {
        if (root == null) return true;
        return false;
    }

    /**
     * This method will find all the close matching Objects within
     * a certain threshold.  For instance, for search for similar
     * strings, threshold set to 1 will return all the strings that
     * are off by 1 edit distance.
     * @param searchObject
     * @param threshold
     * @return
     */
    public HashMap<E, Integer> query(E searchObject, int threshold) {
        matches = new HashMap<E,Integer>();
        root.query(searchObject, threshold, matches);
        return matches;
    }

    /**
     * Attempts to find the closest match to the search term.
     * @param term
     * @return the edit distance of the best match
     */
    public int find(E term) {
        return root.findBestMatch(term, Integer.MAX_VALUE);
    }

    /**
     * Attempts to find the closest match to the search term.
     * @param term
     * @return a match that is within the best edit distance of the search term.
     */
    public E findBestWordMatch(E term) {
        root.findBestMatch(term, Integer.MAX_VALUE);
        return root.getBestTerm();
    }

    /**
     * Attempts to find the closest match to the search term.
     * @param term
     * @return a match that is within the best edit distance of the search term.
     */
    public HashMap<E,Integer> findBestWordMatchWithDistance(E term) {
        int distance = root.findBestMatch(term, Integer.MAX_VALUE);
        HashMap<E, Integer> returnMap = new HashMap<E, Integer>();
        returnMap.put(root.getBestTerm(), distance);
        return returnMap;
    }

    private class Node {

        E term;
        HashMap<Integer, Node> children;

        public Node(E term) {
            this.term = term;
            children = new HashMap<Integer, Node>();
        }

        public void add(E term) {
            int score = distance.getDistance(term, this.term);

            Node child = children.get(score);
            if(child != null) {
                child.add(term);
            }
            else {
                children.put(score, new Node(term));
            }
        }

        public int findBestMatch(E term, int bestDistance) {
            int distanceAtNode = distance.getDistance(term, this.term);

//			System.out.println("term = " + term + ", this.term = " + this.term + ", distance = " + distanceAtNode);

//			if(distanceAtNode == 1) {
//				return distanceAtNode;
//			}

            if(distanceAtNode < bestDistance) {
                bestDistance = distanceAtNode;
                bestTerm = this.term;
            }

            int possibleBest = bestDistance;

            for (Integer score : children.keySet()) {
                if(score < distanceAtNode + bestDistance ) {
                    possibleBest = children.get(score).findBestMatch(term, bestDistance);
                    if(possibleBest < bestDistance) {
                        bestDistance = possibleBest;
                    }
                }
            }
            return bestDistance;
        }

        public E getBestTerm() {
            return bestTerm;
        }

        public void query(E term, int threshold, HashMap<E, Integer> collected) {
            int distanceAtNode = distance.getDistance(term, this.term);

            if(distanceAtNode == threshold) {
                collected.put(this.term, distanceAtNode);
                return;
            }

            if(distanceAtNode < threshold) {
                collected.put(this.term, distanceAtNode);
            }

            for (int score = distanceAtNode-threshold; score <= threshold+distanceAtNode; score++) {
                Node child = children.get(score);
                if(child != null) {
                    child.query(term, threshold, collected);
                }
            }
        }
    }
}
