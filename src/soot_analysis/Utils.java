package soot_analysis;

import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import soot.Body;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;

public class Utils {
	
	public static void print(Object... oo){
		System.out.println(join("\t", oo));
	}

	public static String join(String sep, Object... oo){
		String tstr = "";
		if(oo==null){
			return null;
		}else{
			for(Object o : oo){
				if(o instanceof Iterable){
					tstr = ">>>" + sep;
					Iterable ii = (Iterable) o;
					Iterator<Object> it = ii.iterator();
					
					while (it.hasNext()){
						Object o2 = it.next();
						if(!(o instanceof String)){
							tstr += String.valueOf(o2);
						}else{
							tstr += (String) o2;
						}
						tstr += sep;
					}
					tstr += "<<<";
				}else if(!(o instanceof String)){
					tstr += String.valueOf(o);
				}else{
					tstr += (String) o;
				}
				tstr += sep;
			}
			
			if(tstr.endsWith(sep)){
				tstr = tstr.substring(0, tstr.length()-1);
			}
			return tstr;
		}
	}
	
	public static String join(Object... oo){
		String sep = "|";
		String tstr = "";
		if(oo==null){
			return null;
		}else{
			for(Object o : oo){
				if(!(o instanceof String)){
					tstr += String.valueOf(o);
				}else{
					tstr += (String) o;
				}
				tstr += sep;
			}
			return tstr;
		}
	}
	
	
	public static String sootClassTypeToString(int value){
		switch(value){
			case SootClass.BODIES:
				return "BODIES";
			case SootClass.DANGLING:
				return "DANGLING";
			case SootClass.HIERARCHY:
				return "HIERARCHY";
			case SootClass.SIGNATURES:
				return "SIGNATURES";
			default:
				return "UNKNOWN";
		}
	}
	
	public static <T> List<T> iterableToList(Iterable<T> c){
		LinkedList<T> res = new LinkedList<T>();
		for(T e : c){
			res.add(e);
		}
		return res;
	}
	
	public static boolean isSupportClass(SootClass targetClass) {
		String cname = targetClass.getName();
		String[] clist = {"android.support.v", "com.google.common.", "junit.", "org.junit."};
		for(String n : clist){
			if(cname.startsWith(n)){
				return true;
			}
		}
		return false;
	}
	
	public static Collection<String> expandToSupportClasses(String className){
		String[] compactVersions = {"v4", "v7", "v8", "v13", "v14", "v17"};
		String pre = "android.";
		
		List<String> classNames = new LinkedList<String>();
		if( className.startsWith(pre)){
			classNames.add(className);
			for(String cv : compactVersions){
				String compatString;
				if(className.contains("$")){
					int i = className.indexOf("$");
					compatString = className.substring(0, i) + "Compat" + className.substring(i);
				}else{
					compatString = className + "Compat";
				}
				classNames.add(pre + "support." + cv + "." + compatString.substring(pre.length()));
			}
		}else{
			classNames.add(className);
		}
		return classNames;
	}
	
	public static void printMethod(String tag, SootMethod mm){
		print(tag, mm.getSignature());
		if(mm.hasActiveBody()){
			for(Unit uu : mm.getActiveBody().getUnits()){
				print(tag, uu, uu.getClass().getSimpleName());
			}
		}else{
			print(tag, "no active body");
		}
	}
	
	public static String strExtract(String tstr, String start, String end){
		String tmp;
		tmp = tstr.substring(tstr.indexOf(start)+start.length());
		return tmp.substring(0, tmp.indexOf(end));
	}
	
	public static boolean stringInList(String s, Collection<String> sl){
		for(String ss : sl){
			if(s.equals(ss)){
				return true;
			}
		}
		return false;
	}
	
	public static boolean isReg(String reg){
		if(! reg.startsWith("$")){
			return false;
		}
		if(reg.contains(".<")){
			return false;
		}
		return true;
	}

	public static boolean isLibraryMethod(SootMethod method) {
		String cname = method.getDeclaringClass().getName();
		String[] clist = {"com.google.", "junit.", "org.junit."};
		for(String n : clist){
			if(cname.startsWith(n)){
				return true;
			}
		}
		return false;
	}

}
