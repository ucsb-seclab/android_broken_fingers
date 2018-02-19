package soot_analysis;

public class Feature{
	String name;
	String value;
	String location;
	String result;
	String slice;
	String extra;
	
	Feature(String name, String value, String location, String result, String slice, String extra){
		this.name = name;
		this.value = value;
		this.location = location;
		this.result = result;
		this.slice = slice;
		this.extra = extra;
	}
}