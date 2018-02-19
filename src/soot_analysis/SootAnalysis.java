package soot_analysis;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import soot.Body;
import soot.G;
import soot.Pack;
import soot.PackManager;
import soot.PatchingChain;
import soot.PhaseOptions;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.SootResolver;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.Constant;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JNewExpr;
import soot.jimple.toolkits.typing.TypeAssigner;
import soot.options.Options;
import soot.util.Chain;
import static soot_analysis.Utils.*;

public class SootAnalysis {
	public static void main(String[] args) {
		if(args[0].equalsIgnoreCase("fp1")){
			fp1(args);
		}
		System.exit(99);
	}
	
	public static void fp1(String[] args){
		Map<String, String> config = new HashMap<String, String>();
		config.put("input_format", "apk");
		config.put("android_sdk", args[1]);
		config.put("ir_format", "shimple");
		config.put("input_file", args[2]);
		
		String ctime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
		print("START_WORKING on ", args[2], "AT", ctime);
		
		String aaptResult = aaptResult(args[2]);
		String md5 = computeMD5(args[2]);
		String pname = strExtract(aaptResult, "package: name='", "'");
		String pversion = strExtract(aaptResult, "versionName='", "'");
		
		SootAnalysis sa = new SootAnalysis();
		Scene ss = null;
		try {
			ss = sa.run(config);
		} catch (Exception e) {
			print("Exception:", e.getMessage());
			print(join("\n",e.getStackTrace()));
			System.exit(33);
		}
		
		SootContext sc = new SootContext(ss);
		
		int nclasses = 0;
		int nmethods = 0;
		for(SootClass c : sc.cm.values()){
			if(c.isApplicationClass()){
				nclasses+=1;
				nmethods+=c.getMethodCount();
			}
		}
		
		Features features = new Features();
		features.addMeta("pname", pname);
		features.addMeta("version", pversion);
		features.addMeta("fname",new File(args[2]).getName());
		features.addMeta("md5", md5);
		features.addMeta("nclasses", String.valueOf(nclasses));
		
		print("=== KeyGen analysis...");
		analyzeKeyGen(features, sc);
		print("=== OnAuthenticationSucceeded analysis...");
		analyzeOnAuthenticationSucceeded(features, sc);
		print("=== AuthenticationRequired analysis...");
		analyzeAuthenticationRequired(features, sc);
		print("=== Authenticate analysis...");
		analyzeAuthenticate(features, sc);
		print("=== Analyses are done");
		
		print("================================= JSON START");
		print(features.toJson());
		print("================================= JSON END");
		
		print("=== FEATURES:");
		print(features);
		print("=== NCLASSES: " + String.valueOf(nclasses));
		print("=== NMETHODS: " + String.valueOf(nmethods));

		ctime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
		print(args[2], "END", "AT", ctime);
	}
	
	private static void analyzeKeyGen(Features features, SootContext SC) {
		Collection<CodeLocation> usages = SC.getAPIUsage("android.security.keystore.KeyGenParameterSpec$Builder", "void <init>(java.lang.String,int)", false, false);

		for(CodeLocation cl : usages){
			Value vv = getInvokeParameter(SC, cl.sunit, 1);
			String result;
			if(handleIntFlag(SC, cl, vv, 4, "and")){ //4 --> SIGN
				result = "Asymm";
			}else{
				result = "Symm";
			}
			features.add("Keybuilder", vv, cl, result, "", SC.getInvokeExpr(cl.sunit));
		}
		
		//these exotic ones does not have "setUserAuthenticationRequired", therefore cannot be used securely, as far as I understand
		SootClass scc = SC.cm.get("java.security.spec.AlgorithmParameterSpec");
		if(scc == null){
			return;
		}
		List<SootClass> scl = SC.ch.getDirectImplementersOf(scc);
		List<String> exotic_classes = new LinkedList<String>();
		for(SootClass sc : scl){
			if(sc.getShortName().equals("KeyGenParameterSpec")){
				continue;
			}
			exotic_classes.add(sc.getName()+"$Builder");
		}
		Collection<CodeLocation> exotic_usages = SC.getAPIUsage(exotic_classes, "void <init>", true, false);

		for(CodeLocation cl : exotic_usages){
			String result = "Exotic";
			features.add("Keybuilder", SC.getInvokeExpr(cl.sunit).getMethod().getDeclaringClass().getShortName(), cl, result, "", SC.getInvokeExpr(cl.sunit));
		}
	}
	
	private static void analyzeAuthenticate(Features features, SootContext SC) {
		Collection<CodeLocation> usages = new LinkedList<CodeLocation>();
		for(String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager")){
			usages.addAll(SC.getAPIUsage(className, "void authenticate", true, true));
		}
		//in this case it could be that they are using obfuscated wrapper library
		//I assume that they don't use both obfuscated wrapper library and direct call
		//to counteract this we consider also calls from the wrapper library (app -> w -> framework, typically we consider just app, instead now we consider w)
		//it would be better to detect app, however app and w may have different signature (it seems that authenticate in w is always weak)
		if(usages.size() == 0){
			usages.addAll(SC.getAPIUsage("android.hardware.fingerprint.FingerprintManager", "void authenticate", true, false));
		}
		
		//filtering usages in framework which are not really used.
		Collection<CodeLocation> usages_filtered = new LinkedList<CodeLocation>();
		for(CodeLocation cl : usages){
			if(! isSupportClass(cl.smethod.getDeclaringClass())){
				usages_filtered.add(cl);
				continue;
			}
			// this is needed for instance in com.vzw.hss.myverizon
			Collection<CodeLocation> sml = SC.getCallers(cl.smethod);
			BackwardCallgraph bc = new BackwardCallgraph(SC, cl.smethod);
			Tree<CallgraphState> btree = bc.run(20);
			
			for(Node<CallgraphState> ncs : btree.nodeMap.values()){
				CallgraphState cs = ncs.value;
				if(! isSupportClass(cs.method.getDeclaringClass())){
					usages_filtered.add(cl);
					break;
				}
			}
		}
		
		for(CodeLocation cl : usages_filtered){
			Value vv = getInvokeParameter(SC,cl.sunit, 0);  
			String result;
			String slice = "";
			if(handleIntFlag(SC, cl, vv, 0, "equal")){
				result = "Weak";
			}else{
				String reg = String.valueOf(vv);
				
				Slicer sl = new Slicer(SC, cl.sunit, reg, cl.smethod);
				sl.followMethodParams = true;
				sl.followReturns = true;
				sl.followFields = true;
				Tree<SlicerState>  stree = sl.run(20);
				
				if(isNullSliceForAuthenticate(stree)){
					result = "Weak";
				}else{
					result = "Strong";
				}
				
				slice = String.valueOf(stree);
			}
			
			
			features.add("Authenticate", vv, cl, result, slice, SC.getInvokeExpr(cl.sunit));
		}
		
	}

	private static void analyzeOnAuthenticationSucceeded(Features features, SootContext SC) {
		Collection<SootMethod> possibleTargets = new LinkedList<SootMethod>();
		SootClass sc = SC.cm.get("java.security.Signature");
		if(sc!=null){
			for(SootMethod mm : sc.getMethods()){
				if(mm.getSubSignature().contains("sign(")|| mm.getSubSignature().contains(" update(")){
					possibleTargets.add(mm);
				}
			}
		}
		sc = SC.cm.get("javax.crypto.Cipher");
		if(sc!=null){
			for(SootMethod mm : sc.getMethods()){
				if(mm.getSubSignature().contains("doFinal(")|| mm.getSubSignature().contains(" update(")){
					possibleTargets.add(mm);
				}
			}
		}
		
		Collection<Tree<CallgraphState>> possibleTargetsTrees = new LinkedList<Tree<CallgraphState>>();
		for(SootMethod mm : possibleTargets){
			BackwardCallgraph bc = new BackwardCallgraph(SC, mm);
			bc.skipLibraries = true;
			Tree<CallgraphState> tree = bc.run(200);
			if(tree.nodeMap.size()>1){
				possibleTargetsTrees.add(tree);
			}
		}
		
		
		Collection<SootMethod> succeededUsages = new LinkedList<SootMethod>();
		for(String className : Utils.expandToSupportClasses("android.hardware.fingerprint.FingerprintManager$AuthenticationCallback")){
			SootMethod mm = SC.resolveMethod(className, "void onAuthenticationSucceeded", true);
			if(mm==null){
				continue;
			}
			Collection<SootMethod> tusages = SC.getOverrides(mm);
			succeededUsages.addAll(tusages);
		}

		Collection<SootMethod> succeededUsages_filtered = new LinkedList<SootMethod>();
		for(SootMethod m : succeededUsages){
			if(Utils.isSupportClass(m.getDeclaringClass())){
				continue;
			} 
			succeededUsages_filtered.add(m);
		}
		//in this case it could be that they are using obfuscated wrapper library
		//I assume that they don't use both obfuscated wrapper library and direct call
		//to counteract this we consider also calls from the wrapper library (app -> w -> framework, typically we consider just app, instead now we consider w)
		//it would be better to detect app, however app and w may have different signature (it seems that authenticate in w is always weak)
		if(succeededUsages_filtered.size() == 0){
			succeededUsages_filtered = succeededUsages;
		}
		//I cannot really filter here to see if it is really used, since it is a callback the cg does not give me enough info.
				
		for(SootMethod m : succeededUsages_filtered){
			
			ForwardCallgraph fc = new ForwardCallgraph(SC, m);
			Tree<CallgraphState> tree = fc.run();
			
			boolean found_something = false;
			
			for(Tree<CallgraphState> btree : possibleTargetsTrees){
				Tree<CallgraphState> connectedTree = intersectTrees(tree, btree);
				if(connectedTree==null){
					continue;
				}

				for(Node<CallgraphState> n : connectedTree.nodeMap.values()){
					SootMethod m2 = n.value.method;
					String cname = m2.getDeclaringClass().getName();
					String mname = m2.getSubSignature();
					if(cname.equals("java.security.Signature")){
						if(mname.contains("sign(")|| mname.contains(" update(")){
							Tuple<Unit, InvokeExpr> u_i = SC.recoverEdge(n.value.method, n.parent.value.method);
							if(u_i == null){
								continue;
							}
							Unit uu = u_i.x;
							InvokeExpr ie = u_i.y;
							String extra = "";
							if(mname.contains("update(")){
								Value vv2 = ie.getArgs().get(0);
								String reg = String.valueOf(vv2);
								if(reg.startsWith("$")){
									Slicer sl = new Slicer(SC, uu, reg, n.parent.value.method);
									Tree<SlicerState>  stree = sl.run(20);
									extra = String.valueOf(stree);
								}else{
									extra = String.valueOf(reg);
								}
							}
							features.add("Succeeded", m2.getSignature(), join(",",new Object[] {m, uu, n.parent.value.method}), "Asymm", tree, extra);
							found_something = true;
						}
					}
					if(cname.equals("javax.crypto.Cipher")){ 
						if(mname.contains("doFinal(") || mname.contains(" update(")){ //update seems needed at least for ebay
							Tuple<Unit, InvokeExpr> u_i = SC.recoverEdge(n.value.method, n.parent.value.method);
							if(u_i == null){
								continue;
							}
							Unit uu = u_i.x;
							InvokeExpr ie = u_i.y;
						
							if(mname.contains("doFinal(")){
								boolean isEncryptingConstant = false;
								if(ie.getArgs().size()==1){
									String reg = String.valueOf(ie.getArg(0));
									if(reg.startsWith("$")){
										Slicer sl = new Slicer(SC, uu, reg, n.parent.value.method);
										sl.skipThisReg = false;
										sl.followMethodParams = true;
										Tree<SlicerState> stree = sl.run(20);
										isEncryptingConstant = isSliceToConstant(stree);
									}
								}
								// check if result is not used, or if what is encrypted is constant
								if (isEncryptingConstant || uu.getDefBoxes().size() == 0){
									features.add("Succeeded", m2.getSignature(), join(",",new Object[] {m, uu, n.parent.value.method}), "Weak", tree, "");
								}else{
									features.add("Succeeded", m2.getSignature(), join(",",new Object[] {m, uu, n.parent.value.method}), "Symm", tree, "");
								}
							}else{
								features.add("Succeeded", m2.getSignature(), join(",",new Object[] {m, uu, n.parent.value.method}), "Symm", tree, "");
							}

							found_something = true;
						}
					}
				}
			}

			if(! found_something){
				features.add("Succeeded", "", join(",",new Object[] {m, null, null}), "Unknown", tree, "");
			}
		}
		
	}

	private static Tree<CallgraphState> intersectTrees(Tree<CallgraphState> ft, Tree<CallgraphState> bt){
		HashMap<SootMethod, Node<CallgraphState>> ftmap = new HashMap<>();
		for(Node<CallgraphState> n : ft.nodeMap.values()){
			SootMethod mm = n.value.method;
			int level = n.level;
			if(! ftmap.containsKey(mm) || ftmap.get(mm).level > level){
				ftmap.put(mm, n);
			}
		}
		HashMap<SootMethod, Node<CallgraphState>> btmap = new HashMap<>();
		for(Node<CallgraphState> n : bt.nodeMap.values()){
			SootMethod mm = n.value.method;
			int level = n.level;
			if(! btmap.containsKey(mm) || btmap.get(mm).level > level){
				btmap.put(mm, n);
			}
		}
		
		int candidateDepthF = Integer.MAX_VALUE;
		int candidateDepthB = Integer.MAX_VALUE;
		Node<CallgraphState> c1 = null;
		Node<CallgraphState> c2 = null;
		for(Entry<SootMethod, Node<CallgraphState>>  ee : ftmap.entrySet()){
			SootMethod mm = ee.getKey();
			Node<CallgraphState> n1 = ee.getValue();
			Node<CallgraphState> n2 = btmap.get(mm);
			if(n2!=null){
				int depthF = n1.level;
				int depthB = n2.level;
				if(depthB < candidateDepthB || (depthB == candidateDepthB && depthF < candidateDepthF)){
					candidateDepthF = depthF;
					candidateDepthB = depthB;
					c1 = n1;
					c2 = n2;
				}
			}	
		}

		Tree<CallgraphState> res = null;
		if(c1!=null && c2!=null){
			res = new Tree<>();
			Node<CallgraphState> cnode = c1;
			List<Node<CallgraphState>> nlist = new LinkedList<>();
			while(cnode != null){
				nlist.add(0, cnode);
				cnode = cnode.parent;
			}
			Node<CallgraphState> prev = new Node<CallgraphState>(nlist.get(0));
			prev.level = 0;
			nlist.remove(0);
			res.addHead(prev);
			for(Node<CallgraphState> n : nlist){
				prev = res.addChild(prev, n.value);
			}
			cnode = c2;
			while(cnode != null){
				prev = res.addChild(prev, cnode.value);
				cnode = cnode.parent;
			}
		}
		
		
		return res;
	}
	
	private static void analyzeAuthenticationRequired(Features features, SootContext SC){
		Collection<CodeLocation> usages = SC.getAPIUsage("android.security.keystore.KeyGenParameterSpec$Builder", "android.security.keystore.KeyGenParameterSpec$Builder setUserAuthenticationRequired(boolean)", false, false);
		for(CodeLocation cl : usages){
			Value vv = getInvokeParameter(SC,cl.sunit, 0);
			features.add("AuthenticationRequired", vv, cl, "", "KeyGenParameterSpec$Builder", SC.getInvokeExpr(cl.sunit));
		}
		usages = SC.getAPIUsage("android.security.keystore.KeyProtection$Builder", "android.security.keystore.KeyProtection$Builder setUserAuthenticationRequired(boolean)", false, false);
		for(CodeLocation cl : usages){
			Value vv = getInvokeParameter(SC,cl.sunit, 0);
			features.add("AuthenticationRequired", vv, cl, "", "KeyProtection$Builder", SC.getInvokeExpr(cl.sunit));
		}
	} 
	
	private static boolean handleIntFlag(SootContext SC, CodeLocation cl, Value sv, int targetFlag, String matchType){
		int finalValue;
		String valueString = sv.toString();
		
		if(targetFlag == 0 & valueString.equals("null")){
			if(matchType.equals("equal")){
					return true;
			}
		}
		
		if(sv.getType().toString().equals("int")){
			finalValue = Integer.valueOf(valueString);
			if(matchType.equals("and")){
				if((finalValue & targetFlag)!=0){
					return true;
				}
			}else if(matchType.equals("equal")){
				if(finalValue == targetFlag){
					return true;
				}
			}
		}else if(valueString.startsWith("$")){
			Slicer ss = new Slicer(SC, cl.sunit, valueString, cl.smethod);
			ss.run();
		}
		return false;
	}
	
	private static Value getInvokeParameter(SootContext SC, Unit uu, int argIndex){
		// 0 is the first arg and NOT "this"
		return SC.getInvokeExpr(uu).getArgs().get(argIndex);
	}

	public Scene run(Map<String,String> config) throws Exception{
		String input = config.get("input_file");
		Options.v().set_process_dir(Collections.singletonList(input));
		
		if(config.get("input_format").equals("apk")){
			Options.v().set_android_jars(config.get("android_sdk")); // Android/Sdk/platforms
			Options.v().set_process_multiple_dex(true);
			Options.v().set_src_prec(Options.src_prec_apk);
		}else if(config.get("input_format").equals("jar")){
			Options.v().set_soot_classpath(config.get("soot_classpath"));
		}else{
			throw(new Exception("invalid input type"));
		}
		
		if(config.get("ir_format").equals("jimple")){
			Options.v().set_output_format(Options.output_format_jimple);
		}else if(config.get("ir_format").equals("shimple")){
			Options.v().set_output_format(Options.output_format_shimple);
		}else{
			throw(new Exception("invalid ir format"));
		}
		
		Options.v().set_allow_phantom_refs(true);
		Options.v().setPhaseOption("cg", "all-reachable:true"); 
				
		Options.v().setPhaseOption("jb.dae", "enabled:false");
		Options.v().setPhaseOption("jb.uce", "enabled:false");
		Options.v().setPhaseOption("jj.dae", "enabled:false");
		Options.v().setPhaseOption("jj.uce", "enabled:false");
				
		Options.v().set_wrong_staticness(Options.wrong_staticness_ignore); //should be fixed in newer soot

		Scene.v().loadNecessaryClasses();
		PackManager.v().runPacks();
		System.gc();
		
		print("Soot is done!");
		
		return Scene.v();
	}
	
	public void stop(){
		System.exit(0);
	}
	
	public String connectionTest(String p1){
		return p1+" SUCCESS!";
	}
	
	public static String aaptResult(String fname){
		URL jarLocationUrl = SootAnalysis.class.getProtectionDomain().getCodeSource().getLocation();
		String jarLocation = new File(jarLocationUrl.toString().replace("file:","")).getParent();
		String aaptLocation = new File(jarLocation).toString().concat("/aapt/aapt").toString();
		String tstr = "";

		try {
			String [] args = new String[] {aaptLocation, "dump", "badging", fname};
			print(Utils.join(" ", args));
			Process exec = Runtime.getRuntime().exec(args);
			BufferedReader stdOut = new BufferedReader(new InputStreamReader(exec.getInputStream()));
			exec.waitFor();
			String s = null;
			while ((s = stdOut.readLine()) != null) {
			    tstr += s + "\n";
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return tstr;
	}
	
	private static boolean isSliceToConstant(Tree<SlicerState> stree) {
		SlicerState leaf = null;
		for(SlicerState ss : stree.getLeaves()){
			if(! String.valueOf(ss.reg).equals("return")){
				if(leaf != null){
					return false;
				}else{
					leaf = ss;
				}
			}
		}
		if(leaf!=null){
			if(leaf.unit.getUseBoxes().size() == 1){
				if(Constant.class.isAssignableFrom(leaf.unit.getUseBoxes().get(0).getValue().getClass())){
					return true;
				}
			}
		}
		
		return false;
	}

	
	private static boolean isNullSliceForAuthenticate(Tree<SlicerState> stree) {
		
		for(SlicerState ss : stree.getLeaves()){
			if(stringInList(String.valueOf(ss.reg), Arrays.asList(new String[] {"field", "nullreg"}))){
				continue;
			}
			if(String.valueOf(ss.reg).startsWith("@this")){
				continue;
			}
			if(String.valueOf(ss.reg).equals("return")){
				if(String.valueOf(ss.unit).contains("android.hardware.fingerprint.FingerprintManager$CryptoObject: void <init>")){
					continue;
				}
			}
			return false;
		}
		return true;
	}
	
	//https://www.mkyong.com/java/java-md5-hashing-example/
	public static String computeMD5(String fname){
        MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
        FileInputStream fis = null;
		try {
			fis = new FileInputStream(fname);
		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		}

        byte[] dataBytes = new byte[1024];
        int nread = 0;
        try {
			while ((nread = fis.read(dataBytes)) != -1) {
			  md.update(dataBytes, 0, nread);
			}
		} catch (IOException e) {
			e.printStackTrace();
		};
        byte[] mdbytes = md.digest();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < mdbytes.length; i++) {
          sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        StringBuffer hexString = new StringBuffer();
    	for (int i=0;i<mdbytes.length;i++) {
    		String hex=Integer.toHexString(0xff & mdbytes[i]);
   	     	if(hex.length()==1) hexString.append('0');
   	     	hexString.append(hex);
    	}
    	return hexString.toString();
    }	
}
