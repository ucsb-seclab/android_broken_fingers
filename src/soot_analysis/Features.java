package soot_analysis;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.LinkedList;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.HashMap;

public class Features {
	public Collection<Feature> flist = new LinkedList<Feature>();
	HashMap<String, String> meta = new HashMap<String, String>();
	
	public Features(){
		;
	}
	
	public void add(String name, Object value, Object location, String result, Object slice, Object extra){
		flist.add(new Feature(String.valueOf(name), String.valueOf(value), String.valueOf(location), result, String.valueOf(slice), String.valueOf(extra)));
	}
	
	public String toJson(){
		HashMap<String, Object> finalResult = new HashMap<String, Object>();
		finalResult.put("meta", meta);
		finalResult.put("features", flist);
		
		Gson gson = new GsonBuilder().create();
		String res = gson.toJson(finalResult);
		return res;
	}
	
	public String toString(){
		String tstr = "\n";
		for(Feature f : flist){
			tstr += "-> "+String.valueOf(f.name)+":"+String.valueOf(f.value)+"="+String.valueOf(f.result)+"_"+String.valueOf(f.location)+"\n";
		}
		if(tstr.endsWith("\n")){
			tstr = tstr.substring(0, tstr.length()-1);
		}
		return tstr;
	}

	public void addMeta(String key, String value) {
		meta.put(key, value);
	}

}
