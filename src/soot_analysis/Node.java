package soot_analysis;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import static soot_analysis.Utils.*;

public class Node<T> {
	public Node<T> parent;
	public List<Node<T>> children  = new LinkedList<Node<T>>();
	public T value;
	public int level;
	
	public Node(int level){
		this.level = level;
	}
	
	public Node(Node<T> on){
		this.level = on.level;
		this.value = on.value;
	}
	
	public String toString(){
		return toString(null, 0, false);
	}
	
	public String toString(HashSet<String> limiter, int i) {
		return toString(limiter, i, false);
	}
	
	public String toFullString(HashSet<String> limiter, int i) {
		return toString(limiter, 0, true);
	}
	 
	public String toString(HashSet<String> limiter, int limitedLevel, boolean printParent){
		boolean last = false;

		
		int indentSteps = level;
		if(limiter!=null){
			String hash = ((Hashable) value).getHash();
			if(limiter.contains(hash)){
				last = true;
				indentSteps = limitedLevel;
			}else{
				limiter.add(hash);
			}
		}
		String indent = "";
		for(int i=0;i<indentSteps;i++){
			indent += "-";
		}
		String res = indent + "N" + String.valueOf(level) + ":" + String.valueOf(value);
		if(printParent){
			String pvalue = "nullparent";
			if(parent != null){
				pvalue = String.valueOf(parent.value);
			}
			res += ":p:" + pvalue;
		}
		if(last){
			res += "-->";
		}else{
			for(Node<T> n : children){
				res += "\n" + n.toString(limiter, level+1, printParent);
			}
		}
		return res;
	}
}
