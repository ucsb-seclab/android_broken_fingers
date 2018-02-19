package soot_analysis;

import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.UnitBox;
import soot.Value;
import soot.ValueBox;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.internal.JInvokeStmt;
import soot.toolkits.graph.ExceptionalUnitGraph;

import static soot_analysis.Utils.*;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;

public class ForwardSlicer {
	
	Unit startUnit;
	String startReg;
	SootMethod containerMethod;
	SootContext SC;
	int maxNNodes = 200;
	
	public ForwardSlicer(SootContext SC, Unit startUnit, String startReg, SootMethod containerMethod){
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
            SlicerState sstate_pre = cn.value;
            Collection<Tuple<Unit, SootMethod>> toExploreUnits;
        	toExploreUnits = new LinkedList<>();

            if(sstate_pre.reg.equals("return")){
            	for(CodeLocation cl : SC.getCallers(sstate_pre.containerMethod)){
            		toExploreUnits.add(new Tuple(cl.sunit, cl.smethod));
            	}
            }else{
            	for(Unit newUnit : SC.getUseUnits(sstate_pre.reg, sstate_pre.containerMethod)){
            		toExploreUnits.add(new Tuple(newUnit, sstate_pre.containerMethod));
            	}
            }
            
            for(Tuple<Unit, SootMethod> tstate : toExploreUnits){
				boolean added = false;
            	for(ValueBox vb : unitToBoxes(tstate.x)){
            		String uureg = vb.getValue().toString();
            		if(! uureg.startsWith("$")){
            			continue;
            		}
            		added = true;
            		Node<SlicerState> nn = tree.addChild(cn, new SlicerState(uureg, tstate.x, tstate.y));
            		if(nn != null){
            			queue.add(nn);
            		}
            	}
            	if(! added){
            		if(tstate.x.getClass().getSimpleName().equals("JReturnStmt")){
                		Node<SlicerState> nn = tree.addChild(cn, new SlicerState("return", tstate.x, tstate.y));
                		if(nn != null){
                			queue.add(nn);
                		}
            		}else{
            			tree.addChild(cn, new SlicerState(null, tstate.x, tstate.y));
            		}
            	}
            }
        }
                
        return tree;
	}
	
	public Collection<ValueBox> unitToBoxes(Unit uu){
		LinkedList<ValueBox> vblist = new LinkedList<>(uu.getDefBoxes());
		InvokeExpr ie = SC.getInvokeExpr(uu); //add this, to deal with e.g., constructors
		if(ie != null){
			if(ie instanceof InstanceInvokeExpr){
				InstanceInvokeExpr iie = (InstanceInvokeExpr) ie;
				ValueBox newBox = iie.getBaseBox();
				if(! (vblist.contains(newBox))){
					vblist.add(iie.getBaseBox());
				}
			}
		}
		return vblist;
	}
}


