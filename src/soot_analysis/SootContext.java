package soot_analysis;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;

import soot.Body;
import soot.Hierarchy;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.SootMethodRef;
import soot.SootResolver;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.FieldRef;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Stmt;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInstanceFieldRef;
import soot.jimple.internal.JInterfaceInvokeExpr;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JNewExpr;
import soot.jimple.internal.JSpecialInvokeExpr;
import soot.jimple.internal.JStaticInvokeExpr;
import soot.jimple.internal.JVirtualInvokeExpr;
import static soot_analysis.Utils.*;


public class SootContext {
	public Scene scene;
	public Hierarchy ch;
	public HashMap<String, SootClass> cm = new HashMap<String, SootClass>();
	public HashMap<SootMethod, HashSet<CodeLocation>> callers_cache = new HashMap<SootMethod, HashSet<CodeLocation>>();
	public HashMap<SootMethod, HashMap<String, Unit>> def_cache = new HashMap<SootMethod, HashMap<String, Unit>>();
	public HashMap<SootMethod, HashMap<String, Collection<Unit>>> use_cache = new HashMap<SootMethod, HashMap<String, Collection<Unit>>>();
	public HashMap<SootField, HashSet<Tuple<Unit, SootMethod>>> field_cache = new HashMap<>();
	
	private Collection<SootMethod> runnableRunMethods;
	
	SootContext(Scene s){
		this.scene = s;
		ch = new Hierarchy();
		for(SootClass sc : this.scene.getClasses()){
			cm.put(sc.getName(), sc);
			if(sc.resolvingLevel() == SootClass.HIERARCHY){
				SootResolver.v().reResolve(sc, SootClass.SIGNATURES);
			}
		}
		
		long old = System.currentTimeMillis();
		for(SootClass sc : this.scene.getClasses()){
			if(sc.resolvingLevel() == SootClass.BODIES){
				for(SootMethod sm : sc.getMethods()){
					if(!sm.hasActiveBody()){
						continue;
					}
					for(Unit uu: sm.getActiveBody().getUnits()){
						for(ValueBox db : uu.getDefBoxes()){
							Value vv = db.getValue();
							try{
								FieldRef iff = (FieldRef) vv;
								SootField ff = iff.getField();
								HashSet<Tuple<Unit, SootMethod>> current_set = field_cache.get(ff);
								if(current_set == null){
									current_set = new HashSet<Tuple<Unit, SootMethod>>();
									field_cache.put(ff, current_set);
								}
								current_set.add(new Tuple(uu, sm));
							}catch(ClassCastException e){
								continue;
							}
						}
					}
				}
			}
		}
		print("FIELD_MAP done in: " + String.valueOf(System.currentTimeMillis()-old));		
	}
	
	public List<InvokeExpr> getInvokes(SootMethod m){
		List<InvokeExpr> res = new ArrayList<InvokeExpr>();
		if(m.hasActiveBody()){
			Body bb = m.getActiveBody();
			for(Unit uu : bb.getUnits()){
				InvokeExpr ie = getInvokeExpr(uu);
				if(ie!=null){
					res.add(ie);
				}
			}
		}
		return res;
	}
	
	public List<Tuple<Unit, InvokeExpr>> getInvokesWithUnit(SootMethod m){
		List<Tuple<Unit, InvokeExpr>> res = new ArrayList<Tuple<Unit, InvokeExpr>>();
		if(m.hasActiveBody()){
			Body bb = m.getActiveBody();
			for(Unit uu : bb.getUnits()){
				InvokeExpr ie = getInvokeExpr(uu);
				if(ie!=null){
					res.add(new Tuple<Unit, InvokeExpr>(uu, ie));
				}
			}
		}
		return res;
	}
	
	public InvokeExpr getInvokeExpr(Unit uu){
		Stmt ss = null;
		InvokeExpr res = null;
		try{
			ss = (Stmt)uu;
		}catch(ClassCastException e){
			return null;
		}
		try{
			res = ss.getInvokeExpr();
		}catch(RuntimeException e){
			return null;
		}
		return res;
	}
	
	public List<SootMethod> getCallees(InvokeExpr ie, SootMethod container){
		//the problem is that we don't have a MethodRef m1 in C if m1 is not really implemented in C, but we just have a MethodRef
		//the MethodRef is resolved to the implementation of m1 in the nearest superclass of C
		//however when we call the resolving functions, we pass class C as parameter (and not the class of called)
		SootMethod called = (SootMethod) ie.getMethodRef().resolve();
		
		if((ie instanceof JVirtualInvokeExpr) || (ie instanceof JInterfaceInvokeExpr)){
			SootClass target = ie.getMethodRef().declaringClass();
			List<SootMethod> tt;
			try{
				tt = ch.resolveAbstractDispatch(target, called);
			}catch(RuntimeException e){
				tt = new LinkedList<SootMethod>();
			}
			
			if(tt.size() == 0 && !target.isInterface()){
				//this happens when the target is abstract in framework.
				//in this case Soot does not know the existence of a concrete implementation of the method in some subclass in the framework (unless somewhere else the subclass is called directly)
				//this is a workaround, but at least it allows you to have the expected method in the caller list
				tt = new LinkedList<SootMethod>();
				try{
					SootMethod resm = ch.resolveConcreteDispatch(target, called);
					tt.add(resm);
				}catch(RuntimeException e){
					;
				}
			}
			
			return tt;
		}else if(ie instanceof JStaticInvokeExpr){
			SootClass target = ie.getMethodRef().declaringClass();
			SootMethod resm = ch.resolveConcreteDispatch(target, called);
			List<SootMethod> res = new LinkedList<SootMethod>();
			res.add(resm);
			return res;
		}else if(ie instanceof JSpecialInvokeExpr){
			SootMethod resm = ch.resolveSpecialDispatch((JSpecialInvokeExpr)ie, container);
			List<SootMethod> res = new ArrayList<SootMethod>();
			res.add(resm);
			return res;
		}
		
		/*
		in C:
		   DC->m()
		My understanding is that invokestatic and invokespecial are very similar.
		In both cases we can have one only answer, since we start from a single possible concrete class, so we just go up in a line.
		The compiler could resolve static and special before hand but it does not.
		However special is used when the target is a private non-static method.
		
		Static obviously does not pass base.
		Special is like static but:
			in case of private or init it does not dispatch
			it dispatches like static in case DC subclass of C, using C as base of the dispatching
			
		https://github.com/pcpratts/soot-rb/blob/master/src/soot/Hierarchy.java
		*/
		
		return null;
	}
	
	public Collection<SootMethod> getCallees(SootMethod m){
		HashSet<SootMethod> res = new LinkedHashSet<SootMethod>();
		List<InvokeExpr> iel = getInvokes(m);
		for(InvokeExpr ie : iel){
			res.addAll(getCallees(ie, m));
		}
		return res;
	}
	
	//Unit is the calling Unit, Method is the called method
	//Same unit can have different methods
	public Collection<Tuple<Unit, SootMethod>> getCalleesWithUnit(SootMethod m){
		HashSet<Tuple<Unit, SootMethod>> res = new LinkedHashSet<>();
		List<Tuple<Unit, InvokeExpr>> u_ieList = getInvokesWithUnit(m);
		for(Tuple<Unit, InvokeExpr> u_ie : u_ieList){
			for(SootMethod calledMethod : getCallees(u_ie.y, m)){
				res.add(new Tuple<Unit, SootMethod>(u_ie.x, calledMethod));
			}
		}
		return res;
	}
	
	public Collection<CodeLocation> getCallers(SootMethod m){
		HashSet<CodeLocation> res = callers_cache.get(m);
		if(res!=null){
			return res;
		}
		res = new LinkedHashSet<CodeLocation>();
		
		for(SootClass sclass : cm.values()){
			if(! sclass.isApplicationClass()){
				continue;
			}
			
			//solving: Exception in thread "main" java.util.ConcurrentModificationException
			List<SootMethod> copiedMethods = new LinkedList<SootMethod>();
			for(SootMethod tm : sclass.getMethods()){
				copiedMethods.add(tm);
			}

			for(SootMethod tm : copiedMethods){
				if(tm.hasActiveBody()){
					Body bb = tm.getActiveBody();
					for(Unit uu : bb.getUnits()){
						InvokeExpr ie = getInvokeExpr(uu);
						if(ie != null){
							//at least the subsignature must be the same
							if(ie.getMethod().getSubSignature().equals(m.getSubSignature())){
								List<SootMethod> targets = getCallees(ie, tm);
								if(targets.contains(m)){
									res.add(new CodeLocation(sclass, tm , uu));
								}
							}
						}
					}
				}	
			}
		}
		
		callers_cache.put(m, res);
		return res;
	}
	
	public Collection<SootMethod> getOverrides(String className, String methodNameStart){
		HashSet<SootMethod> res = new LinkedHashSet<SootMethod>();
		SootClass sclass = cm.get(className);
		if(sclass == null){
			return res;
		}
		List<SootClass> sclist;
		if(sclass.isInterface()){
			 sclist = ch.getImplementersOf(sclass);
		}else{
			sclist = ch.getSubclassesOf(sclass);
		}
		
		for(SootClass sc : sclist){
				// we only care about concrete implementations here
			for(SootMethod sm : sc.getMethods()){
				if(sm.getSubSignature().startsWith(methodNameStart)){
					res.add(sm);
				}
			}
		}
		return res;
	}
	
	public Collection<SootMethod> getOverrides(SootMethod mm) {
		HashSet<SootMethod> res = new LinkedHashSet<SootMethod>();
		SootClass sclass = cm.get(mm.getDeclaringClass().getName());
		
		List<SootClass> sclist;
		if(sclass.isInterface()){
			 sclist = ch.getImplementersOf(sclass);
		}else{
			sclist = ch.getSubclassesOf(sclass);
		}
		
		for(SootClass sc : sclist){
			// we only care about concrete implementations here
			for(SootMethod sm : sc.getMethods()){
				if(sm.getSubSignature().equals(mm.getSubSignature())){
					res.add(sm);
				}
			}
		}
		return res;
	}	
	
	public Unit getDefUnit(String reg, SootMethod containerMethod, boolean skipNews){ //skipNews typically true
		HashMap<String, Unit> defMap = def_cache.get(containerMethod);
		if(defMap == null){
			defMap = new HashMap<String, Unit>();
			Body bb = containerMethod.getActiveBody();
			for(Unit uu : bb.getUnits()){
				for(ValueBox df : uu.getDefBoxes()){
					String cname = df.getClass().getSimpleName();
					if(cname.equals("LinkedVariableBox") || cname.equals("JimpleLocalBox")){
						
						//if it is reg = new ... we don't want it
						boolean isNewAssignment = isNewAssignment(uu);
						//instead we look for the constructor
						if(isNewAssignment && skipNews){
							Unit uuReal = null;
							for(Unit uu2 : bb.getUnits()){
								InvokeExpr ie = getInvokeExpr(uu2);
								if(ie!=null){
					            	if(ie instanceof InstanceInvokeExpr){
					            		String nreg = ((InstanceInvokeExpr) ie).getBase().toString();
					            		if(nreg.equals(df.getValue().toString()) && ie.getMethod().getSubSignature().startsWith("void <init>")){
					            			uuReal = uu2;
					            		}
					            	}
								}
							}
							if(uuReal != null){
								defMap.put(df.getValue().toString(), uuReal);
								break; //there should not be more than one of type LinkedVariableBox because of SSA
							}
						}
						
						defMap.put(df.getValue().toString(), uu);
						break; //there should not be more than one of type LinkedVariableBox because of SSA
					}
				}
			}
			def_cache.put(containerMethod, defMap);
		}
		Unit res = defMap.get(reg);
		return res;
	}
	
	public boolean isNewAssignment(Unit uu) {
		String newType = null;
		try{
			newType = (((JNewExpr) ((JAssignStmt)uu).getRightOp()).getBaseType().toString());
		}catch(ClassCastException | NullPointerException e){
			;
		}
		boolean res = newType != null;
		return res;
	}

	public Collection<Unit> getUseUnits(String reg, SootMethod containerMethod){
		HashMap<String, Collection<Unit>> useMap = use_cache.get(containerMethod);
		if(useMap == null){
			useMap = new HashMap<String, Collection<Unit>>();
			Body bb = containerMethod.getActiveBody();
			for(Unit uu : bb.getUnits()){
				for(ValueBox df : uu.getUseBoxes()){
					String reg2 = df.getValue().toString();
					if(! reg2.startsWith("$")){
						continue;
					}
					Collection<Unit> useList = useMap.get(reg2);
					if(useList == null){
						useList = new LinkedList<Unit>();
						useList.add(uu);
						useMap.put(reg2, useList);
					}else{
						useList.add(uu);
					}
				}
			}
			use_cache.put(containerMethod, useMap);
		}
		Collection<Unit> res = useMap.get(reg);
		if(res == null){
			res = new LinkedList<Unit>();
		}
		return res;
	}

	public SootMethod resolveMethod(String className, String methodName) {
		return resolveMethod(className, methodName, false);
	}
	
	public SootMethod resolveMethod(String className, String methodName, boolean fuzzy) {
		SootClass sclass = this.cm.get(className);
		if(sclass == null){
			return null;
		}
		
		if(sclass.resolvingLevel() != SootClass.BODIES){
			SootResolver.v().reResolve(sclass, SootClass.BODIES);
		}
		
		SootMethod res = null;
		for(SootMethod m : sclass.getMethods()){
			boolean match;
			if(fuzzy){
				match = m.getSubSignature().startsWith(methodName);
			}else{
				match = m.getSubSignature().equals(methodName);
			}
			if(match){
				return m;
			}
		}
		return res;
	}
	
	public Collection<CodeLocation> getAPIUsage(String className, String methodName, boolean fuzzy, boolean removeSupport){	
		List<String> classNames = new LinkedList<String>();
		classNames.add(className);
		return getAPIUsage(classNames, methodName, fuzzy, removeSupport);
	}
	
	
	public Collection<CodeLocation> getAPIUsage(Collection<String> classNames, String methodName, boolean fuzzy, boolean removeSupport){		
		Collection<CodeLocation> usages = new LinkedList<CodeLocation>();
		for(String currentClassName : classNames){
			SootMethod mm = resolveMethod(currentClassName, methodName, fuzzy);
			if(mm==null){
				continue;
			}
			Collection<CodeLocation> callers = getCallers(mm);
			usages.addAll(callers);
		}

		
		Collection<CodeLocation> use_filtered = new LinkedList<CodeLocation>();
		if(removeSupport){
			for(CodeLocation use : usages){
				if(Utils.isSupportClass(use.sclass)){
					continue;
				}
				use_filtered.add(use);
			}
		}else{
			use_filtered = usages;
		}
		
		return use_filtered;
	}

	public Collection<SootMethod> getRunnableRunMethods(SootClass upperClass) {
		Collection<SootMethod> filteredRunnableRunMethods;
		if(runnableRunMethods == null){
			Collection<SootMethod> tmp = getOverrides(resolveMethod("java.lang.Runnable", "void run()"));
			runnableRunMethods = new LinkedList<SootMethod>();
			for(SootMethod m : tmp){
				SootClass d = m.getDeclaringClass();
				if(d.isApplicationClass() && !isSupportClass(d)){
					runnableRunMethods.add(m);
				}
			}
		}
		
		if(upperClass == null){
			filteredRunnableRunMethods = runnableRunMethods;
		}else{
			filteredRunnableRunMethods = new LinkedList<SootMethod>();
			
			HashSet<SootClass> cset;
			if(! upperClass.isInterface()){
				cset = new HashSet<>(ch.getSubclassesOfIncluding(upperClass));
			}else{
				cset = new HashSet<>(ch.getImplementersOf(upperClass));
			}
			
			for(SootMethod m : runnableRunMethods){
				if(cset.contains(m.getDeclaringClass())){
					filteredRunnableRunMethods.add(m);
				}
			}
		}
		return filteredRunnableRunMethods;
	}
	
	public String sliceToType(Tree<SlicerState> stree) {
		Node<SlicerState> cnode = stree.head;
		SlicerState res = null;
		while(true){
			List<Node<SlicerState>> nonNullChildren = new LinkedList<Node<SlicerState>>();
			for(Node<SlicerState> c : cnode.children){
				if(c.value.reg!=null || isNewAssignment(c.value.unit)){ //new is a null node, but we still want it
					nonNullChildren.add(c);
				}				
			}
			
			if(cnode.value.unit.getClass().getSimpleName().equals("JAssignStmt")){
				JAssignStmt as = (JAssignStmt) cnode.value.unit;
				return String.valueOf(as.getRightOp().getType());
			}
			
			if(nonNullChildren.size() == 1){
				cnode = nonNullChildren.get(0);
			}else{
				return null;
			}
		}
	}
	
	public Tuple<Unit, InvokeExpr> recoverEdge(SootMethod m, SootMethod parentMethod){
		List<Tuple<Unit, InvokeExpr>> iel = getInvokesWithUnit(parentMethod);
		for(Tuple<Unit, InvokeExpr> ie : iel){
			if(ie.y.getMethod() == m){
				return ie;
			}
		}
		return null; //should never happen
	}

	public SootField getFieldAccess(Unit uu) {
		for(ValueBox vb : uu.getUseBoxes()){
			try{
				Value vv = vb.getValue();
				FieldRef iff = (FieldRef) vv;
				SootField ff = iff.getField();
				return ff;
			}catch(ClassCastException e){
				continue;
			}
		}

		return null;
	}
	
	public SootField getFieldAccess(ValueBox vb) {
		try{
			Value vv = vb.getValue();
			FieldRef iff = (FieldRef) vv;
			SootField ff = iff.getField();
			return ff;
		}catch(ClassCastException e){
			return null;
		}
	}


}
