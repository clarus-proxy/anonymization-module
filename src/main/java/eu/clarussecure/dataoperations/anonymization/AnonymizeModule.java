package eu.clarussecure.dataoperations.anonymization;

import eu.clarussecure.dataoperations.*;
import org.w3c.dom.Document;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class AnonymizeModule implements DataOperation {

	public AnonymizeModule(Document document){
		Functions.readProperties(document);
	}

	@Override
	public List<DataOperationCommand> get(String[] attributeNames, Criteria[] criteria) {
		//TODO: this method should be ignored
		return null;
	}

	@Override
	public List<DataOperationResult> get(List<DataOperationCommand> promise, List<String[][]> contents) {
		//TODO: this method should be ignored
		return null;
	}

	@Override
	public List<DataOperationCommand> post(String[] attributeNames, String[][] content) {
		ArrayList<DataOperationCommand> result = new ArrayList<>();
		
		String[][] plainDataAnom = Functions.anonymize(attributeNames, content);

		DataOperationCommand command = new AnonModuleCommand(attributeNames, content, plainDataAnom);
		result.add(command);

		return result;
	}

	@Override
	public List<DataOperationCommand> put(String[] attributeNames, Criteria[] criteria, String[][] contents) {
		//TODO: this method should be ignored;
		return null;
	}

	@Override
	public List<DataOperationCommand> delete(String[] attributeNames, Criteria[] criteria) {
		//TODO: this method should be ignored
		return null;
	}

	@Override
	public List<Map<String,String>> head(String[] attributeNames) {
		List<Map<String,String>> result = new ArrayList<Map<String,String>>();
		HashMap<String,String> mapping = new HashMap<String, String>();
		for (String attributeName : attributeNames) {
			mapping.put(attributeName, attributeName);
		}
		result.add(mapping);
		return result;
	}
}
