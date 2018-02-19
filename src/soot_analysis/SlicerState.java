package soot_analysis;

import soot.SootMethod;
import soot.Unit;
import static soot_analysis.Utils.*;

public class SlicerState implements Hashable{
	public String reg;
	public Unit unit;
	public SootMethod containerMethod;
	
	SlicerState(String reg, Unit unit, SootMethod containerMethod){
		this.reg = reg;
		this.unit = unit;
		this.containerMethod = containerMethod;		
	}	
	
	public String toString(){
		return join("|", reg, unit, containerMethod.getDeclaringClass()+"/"+containerMethod.getSubSignature());	
	}
	
	public String getHash(){
		return join("|", String.valueOf(reg), unit.toString(), containerMethod.getDeclaringClass()+containerMethod.getSubSignature());
	}

}
