package soot_analysis;

import soot.SootMethod;
import soot.Unit;
import static soot_analysis.Utils.*;

public class CallgraphState implements Hashable{
	public SootMethod method;
	public Unit unit = null; //unit is used when it is needed to know who called a method (from things like postDelay)
	
	CallgraphState(SootMethod method){
		this.method = method;		
	}
	
	CallgraphState(SootMethod method, Unit unit){
		this.method = method;
		this.unit = unit;
	}	
	
	public String toString(){
		return method.getSignature() + ":" + String.valueOf(unit);	
	}
	
	public String getHash(){
		return String.valueOf(method.getSignature()) + String.valueOf(unit);
	}

}
