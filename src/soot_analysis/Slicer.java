package soot_analysis;

import soot.Body;
import soot.SootField;
import soot.SootMethod;
import soot.Unit;
import soot.UnitBox;
import soot.Value;
import soot.ValueBox;
import soot.jimple.Constant;
import soot.jimple.FieldRef;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.RValueBox;
import soot.toolkits.graph.ExceptionalUnitGraph;

import static soot_analysis.Utils.*;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;

public class Slicer {
	
	Unit startUnit;
	String startReg;
	SootMethod containerMethod;
	SootContext SC;
	int maxNNodes = 200;
	
	boolean skipNews = true;
	boolean followMethodParams = false;
	boolean skipThisReg = true;
	boolean followReturns = false;
	boolean followFields = false;
	
	//boolean followInvokeParams = false;
	
	public Slicer(SootContext SC, Unit startUnit, String startReg, SootMethod containerMethod){
		this.SC = SC;
		this.startUnit = startUnit;
		this.startReg = startReg;
		this.containerMethod = containerMethod;
	}	

	public Tree<SlicerState> run(){
		return run(maxNNodes);
	}
	
	
	public Tree<SlicerState> run(int nnodes){
		Tree<SlicerState> tree = new Tree<SlicerState>();
		Node<SlicerState> headNode = new Node<SlicerState>(0);
		headNode.value = new SlicerState(startReg, startUnit, containerMethod);
		tree.addHead(headNode);

        LinkedList<Node<SlicerState>> queue = new LinkedList<Node<SlicerState>>();
        queue.add(headNode);
        while (queue.size() > 0 && tree.nodeMap.size() <= nnodes){
            Node<SlicerState> cn = queue.poll();
            
            List<SlicerState> usedlist = new LinkedList<SlicerState>();
            if(cn.value.reg.startsWith("@parameter")){
            	int narg = Integer.parseInt(Utils.strExtract(cn.value.reg, "@parameter", ": "));
            	Collection<CodeLocation> callers = SC.getCallers(cn.value.containerMethod);
            	for(CodeLocation caller : callers){
            		Value vv = SC.getInvokeExpr(caller.sunit).getArg(narg);
            		usedlist.add(new SlicerState(vv.toString(), caller.sunit, caller.smethod));
            	}
            }else if(cn.value.reg.equals("return") && followReturns){
            	List<SootMethod> cl = SC.getCallees(SC.getInvokeExpr(cn.value.unit), cn.value.containerMethod);
            	for(SootMethod sm : cl){
            		for(Unit uu : sm.getActiveBody().getUnits()){
            			if(uu.getClass().getSimpleName().equals("JReturnStmt")){
            				String reg = uu.getUseBoxes().get(0).getValue().toString();
            				if(isReg(reg)){
            					usedlist.add(new SlicerState(reg, uu, sm));
            				}    				
            			}
            		}
            	}
            
        	}else if(cn.value.reg.equals("field") && followFields){
        		SootField sf = SC.getFieldAccess(cn.value.unit);
        		Collection<Tuple<Unit, SootMethod>> users = SC.field_cache.get(sf);
        		if(users != null){
	        		for(Tuple<Unit, SootMethod> u_m : users){
	        			Unit uu = u_m.x;
	        			SootMethod sm = u_m.y;
        				for(ValueBox vb : uu.getUseBoxes()){
        					String reg = vb.getValue().toString();
            				if(isReg(reg)){
            					usedlist.add(new SlicerState(reg, uu, sm));
            				}    
        				}							
	            	}
        		}
            
        	}else{
            	usedlist.add(cn.value);
            }
            
            for(SlicerState def : usedlist){
				if(def.reg.equals("null")){ //this is the case in which we have null as a parameter --> there is nothing to follow
					tree.addChild(cn, new SlicerState("nullreg", def.unit, def.containerMethod));
					continue;
				}
            	
	            Unit newUnit = SC.getDefUnit(def.reg, def.containerMethod, skipNews);
	            if(newUnit == null){
	            	continue;
	            }
	            String thisReg = null;
	            if(skipThisReg){
		            InvokeExpr ie = SC.getInvokeExpr(newUnit);
		            if(ie!=null){ 
		            	if(ie instanceof InstanceInvokeExpr){
		            		thisReg = ((InstanceInvokeExpr) ie).getBase().toString();
		            	}
		            }
		            
	            }
	            
	            for(ValueBox vb : newUnit.getUseBoxes()){
	            	String boxType = vb.getClass().getSimpleName();
	            	InvokeExpr ie = SC.getInvokeExpr(newUnit); //we check this because LinkedRValueBox can be an ie
	            	boolean isNewAssignment = SC.isNewAssignment(newUnit);	
	            	SootField sf = SC.getFieldAccess(vb);
	            	
	            	if(followFields && sf!=null){
						Node<SlicerState> nn = tree.addChild(cn, new SlicerState("field", newUnit, def.containerMethod));
						if(nn!=null){
							queue.add(nn);
						}
	            	}
	            	
					if(stringInList(boxType, Arrays.asList((new String[] {"ImmediateBox", "SValueUnitPair", "JimpleLocalBox", "IdentityRefBox"}))) ||
							(boxType.equals("LinkedRValueBox") && (ie==null || isNewAssignment))){
						String newValue = vb.getValue().toString();
						if(skipThisReg && newValue.equals(thisReg)){ 
							continue;
						}
						if(! skipNews && isNewAssignment){
							tree.addChild(cn, new SlicerState(null, newUnit, def.containerMethod)); 
						}else if(isReg(newValue) || newValue.startsWith("@")){ //LinkedRValueBox contains bad things
							//newValue is a reg, we want to find it
							Node<SlicerState> nn = tree.addChild(cn, new SlicerState(newValue, newUnit, def.containerMethod));

							if(nn!=null){
								if(isReg(newValue)){
					        		queue.add(nn);
								}else if(newValue.startsWith("@") && followMethodParams){
					        		queue.add(nn);
								}
							}
						}else if(Constant.class.isAssignableFrom(vb.getValue().getClass())){ //stuff like $ref = constant
							tree.addChild(cn, new SlicerState(null, newUnit, def.containerMethod)); 
						}
					}else{
						if(ie != null){
							if(ie.getMethod().getDeclaringClass().isApplicationClass()){
								Node<SlicerState> nn = tree.addChild(cn, new SlicerState("return", newUnit, def.containerMethod));
								if(nn!=null){
									queue.add(nn);
								}
							}else{
								tree.addChild(cn, new SlicerState("return", newUnit, def.containerMethod));
							}
						}else{
						
						// as of now x.something(y), we do not follow x<--y
							tree.addChild(cn, new SlicerState(null, newUnit, def.containerMethod)); 
						}
					}
	            }
            }
        }
        
        
        return tree;
	}
}


