package chainlinker;
/*
 * This class separates non-reflective codes from the main code block.
 */

import java.io.InvalidClassException;

public abstract class ReflectivePointFieldFeeder {
	// NOTE:
	// I'm still getting familiar with Java, but if there're anyone knows it better than me,
	// please fix this. I think this part can be better than this.	
		
	// Dummy value objects for class type info 
	protected static Long lValue = 0L;
	protected static Double lfValue = 0.0;
	protected static String sValue = "";
	protected static Boolean bValue = false;	
	
	public void addField (
			Object metricObject, 
			@SuppressWarnings("rawtypes") Class dataTypeClass, 
			Object data
			) throws ClassNotFoundException, InvalidClassException {
		if (dataTypeClass.equals(lValue.getClass())) {
			addLong(metricObject, (long)data);
		} else if (dataTypeClass.equals(lfValue.getClass())) {
			// For double values, additional touch is required as sometimes integer value may be passed.
			if (lValue.getClass() == data.getClass()) {
				// The reason for this double typecasting:
				// http://stackoverflow.com/questions/32757565/java-lang-long-cannot-be-cast-to-java-lang-double
				// https://docs.oracle.com/javase/specs/jls/se7/html/jls-5.html#jls-5.1.3
				addDouble(metricObject, (double)((long)data));
			} else {
				addDouble(metricObject, (double)data);
			}
		} else if (dataTypeClass.equals(sValue.getClass())) {
			addString(metricObject, (String)data);
		} else if (dataTypeClass.equals(bValue.getClass())) {
			addBoolean(metricObject, (Boolean)data);
		} else {
			throw new ClassNotFoundException("Unidentifiable value is detected. Is the JSON data value is correct?");
		}
	}
	
	protected abstract void addString(Object metricObject, String value) throws InvalidClassException;
	protected abstract void addLong(Object metricObject, long value) throws InvalidClassException;
	protected abstract void addDouble(Object metricObject, double value) throws InvalidClassException;
	protected abstract void addBoolean(Object metricObject, boolean value) throws InvalidClassException;
}
