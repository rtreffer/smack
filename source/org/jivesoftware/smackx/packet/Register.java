package org.jivesoftware.smackx.packet;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.provider.IQProvider;
import org.jivesoftware.smack.provider.ProviderManager;
import org.jivesoftware.smack.util.StringUtils;
import org.xmlpull.v1.XmlPullParser;

public class Register extends IQ {
	
	public final static String NAMESPACE="jabber:iq:register";
	public final static String ELEMENT_NAME="query";
	
	private String instructions;
	private List<String> requiredFields;
	private Map<String,String> fields;
	private boolean registered=false;
	private boolean remove=false;
	
	static{
		ProviderManager.getInstance().addIQProvider(ELEMENT_NAME, NAMESPACE, new Provider());
	}
	
	public Register(){
		requiredFields = new ArrayList<String>();
		fields = new HashMap<String,String>();
	}

	@Override
	public String getChildElementXML() {
		StringBuilder builder = new StringBuilder();
		
		builder.append("<"+ELEMENT_NAME+" xmlns='"+NAMESPACE+"'>");
		if(fields.size()>0 && !remove){
			for(String s : fields.keySet()){
				builder.append("<"+s+">");
				builder.append(StringUtils.escapeForXML(fields.get(s)));
				builder.append("</"+s+">");
			}
		}
		else if(remove){
			builder.append("<remove/>");
		}
		builder.append("</"+ELEMENT_NAME+">");
		
		return builder.toString();
	}
	
	public void setUsername(String username){
		if(username!=null){
			fields.put("username", username);
		}
	}
	
	public void setPassword(String password){
		if(password!=null){
			fields.put("password", password);
		}
	}
	
	public void addField(String key, String value){
		fields.put(key, value);
	}
	
	public String getField(String key){
		return fields.get(key);
	}
	
	public List<String> getFieldNames(){
		return new ArrayList<String>(fields.keySet());
	}
	
	void addRequiredField(String field){
		requiredFields.add(field);
	}
	
	void setInstructions(String instruction){
		instructions = instruction;
	}
	
	public String getInstructions(){
		return instructions;
	}
	
	public List<String> getRequiredFields(){
		return requiredFields;
	}
	
	public void setRegistered(boolean registered){
		this.registered = registered;
	}
	
	public boolean isRegistered(){
		return this.registered;
	}
	
	public void setRemove(boolean remove){
		this.remove = remove;
	}
	
	public boolean isRemoving(){
		return this.remove;
	}
	
	public static class Provider implements IQProvider{

		@Override
		public IQ parseIQ(XmlPullParser parser) throws Exception {
			Register retVal = new Register();
			boolean done = false;
			while(!done){
				if(parser.getEventType()==XmlPullParser.START_TAG){
					String name = parser.getName();
					String text = parser.nextText();
					if(name.equals("instructions")){
						retVal.setInstructions(text);
					}
					else if(!name.equals(ELEMENT_NAME) && text==null){
						retVal.addRequiredField(name);
					}
					else if(!name.equals(ELEMENT_NAME) && text!=null){
						retVal.addField(name, text);
					}
					else if(name.equals("registered") && text==null){
						retVal.setRegistered(true);
					}
				}
				
				if(parser.getEventType()==XmlPullParser.END_TAG && 
						parser.getName().equals(ELEMENT_NAME)){
					done=true;
				}
				else{
					parser.next();
				}
			}
			return retVal;
		}
		
	}

}
