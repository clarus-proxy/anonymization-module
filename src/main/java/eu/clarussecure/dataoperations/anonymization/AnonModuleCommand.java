package eu.clarussecure.dataoperations.anonymization;

import java.util.HashMap;
import java.util.Random;

import eu.clarussecure.dataoperations.DataOperationCommand;

/**
 * Created by Alberto Blanco on 25/01/2017.
 */
public class AnonModuleCommand extends DataOperationCommand {

    public AnonModuleCommand(String[] attributeNames, String[][] contents, String[][] protectedContents) {
        super.id = new Random().nextInt();
        super.attributeNames = attributeNames;
        super.protectedAttributeNames = attributeNames;
        super.extraProtectedAttributeNames = null;
        super.extraBinaryContent = null;
        super.mapping = new HashMap<String, String>();
        for (String attributeName : attributeNames) {
            mapping.put(attributeName, attributeName);
        }
        super.protectedContents = protectedContents;
        super.criteria = null;
    }
}
