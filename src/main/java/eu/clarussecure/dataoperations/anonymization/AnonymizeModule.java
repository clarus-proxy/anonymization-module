package eu.clarussecure.dataoperations.anonymization;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Document;

import eu.clarussecure.dataoperations.AttributeNamesUtilities;
import eu.clarussecure.dataoperations.Criteria;
import eu.clarussecure.dataoperations.DataOperation;
import eu.clarussecure.dataoperations.DataOperationCommand;
import eu.clarussecure.dataoperations.DataOperationResult;

public class AnonymizeModule implements DataOperation {

    public AnonymizeModule(Document document) {
        Functions.readProperties(document);
    }

    @Override
    public List<DataOperationCommand> get(String[] attributeNames, Criteria[] criteria) {
        // TODO: this method should be ignored
        return null;
    }

    @Override
    public List<DataOperationResult> get(List<DataOperationCommand> promise, List<String[][]> contents) {
        // TODO: this method should be ignored
        return null;
    }

    @Override
    public List<DataOperationCommand> post(String[] attributeNames, String[][] content) {
        ArrayList<DataOperationCommand> result = new ArrayList<>();

        String[][] plainDataAnom = Functions.anonymize(attributeNames, content);

        // not necessary to resolve resolve protected attribute here
        // (same as clear attribute name). else we should have use
        // AttributeNamesUtilities.resolveProtectedAttributeName()
        DataOperationCommand command = new AnonModuleCommand(attributeNames, content, plainDataAnom);
        result.add(command);

        return result;
    }

    @Override
    public List<DataOperationCommand> put(String[] attributeNames, Criteria[] criteria, String[][] contents) {
        // TODO: this method should be ignored;
        return null;
    }

    @Override
    public List<DataOperationCommand> delete(String[] attributeNames, Criteria[] criteria) {
        // TODO: this method should be ignored
        return null;
    }

    @Override
    public List<Map<String, String>> head(String[] attributeNames) {
        List<Map<String, String>> result = new ArrayList<Map<String, String>>();
        HashMap<String, String> mapping = new HashMap<String, String>();
        // AKKA fix: resolve attribute names in order to remove any asterisk (*)
        for (String attributeName : AttributeNamesUtilities.resolveOperationAttributeNames(attributeNames,
                Record.refListNames)) {
            // don't map attributes that are not supposed to be protected
            boolean matches = Record.refListNamePatterns.stream().anyMatch(p -> p.matcher(attributeName).matches());
            if (matches) {
                // not necessary to resolve resolve protected attribute here
                // (same as clear attribute name). else we should have use
                // AttributeNamesUtilities.resolveProtectedAttributeName()
                String protectedAttributeName = attributeName;
                mapping.put(attributeName, protectedAttributeName);
            }
        }
        result.add(mapping);
        return result;
    }
}
