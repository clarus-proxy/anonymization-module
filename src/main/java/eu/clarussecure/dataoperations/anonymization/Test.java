package eu.clarussecure.dataoperations.anonymization;

import java.io.*;
import java.util.List;

import eu.clarussecure.dataoperations.DataOperation;
import eu.clarussecure.dataoperations.DataOperationCommand;
import org.w3c.dom.Document;

public class Test {

    public static void main(String[] args) throws IOException {
        String[] attributes;
        String[][] dataOri;
        List<DataOperationCommand> dataAnom;
        byte[] xmlProperties;
        Document document;
        DatasetParser datasetParser;
        File file;

        xmlProperties = loadXmlFile("./datasets/propertiesNoOrderSin_dis_id.xml");
        document = Functions.readDocument(xmlProperties);
        DataOperation interFace = new AnonymizeModule(document);

        file = new File("./datasets/data_clarus_peq.txt");
        datasetParser = new DatasetParser(file, ",");

        attributes = datasetParser.parseHeaders();
        dataOri = datasetParser.parseDataset();
        dataAnom = interFace.post(attributes, dataOri);

        //		xmlProperties = loadXmlFile("./datasets/propertiesNoOrder.xml");
        //		document = Functions.readDocument(xmlProperties);
        //		DataOperation interFace = new AnonymizeModule(document);
        //
        //		file = new File("./datasets/data_clarus2.txt");
        //		datasetParser = new DatasetParser(file , ",");
        //
        //		attributes = datasetParser.parseHeaders();
        //		dataOri = datasetParser.parseDataset();
        //		dataAnom = interFace.post(attributes, dataOri);

        //		xmlProperties = loadXmlFile("./datasets/properties2.xml");
        //		document = Functions.readDocument(xmlProperties);
        //		DataOperation interFace = new AnonymizeModule(document);
        //
        //		file = new File("./datasets/data_clarus2.txt");
        //		datasetParser = new DatasetParser(file, ",");
        //
        //		attributes = datasetParser.parseHeaders();
        //		dataOri = datasetParser.parseDataset();
        //		dataAnom = interFace.post(attributes, dataOri);

        //		xmlProperties = loadXmlFile("./datasets/properties4.xml");
        //		document = Functions.readDocument(xmlProperties);
        //		DataOperation interFace = new AnonymizeModule(document);
        //
        //		file = new File("./datasets/boreholes2.txt");
        //		datasetParser = new DatasetParser(file , ";");
        //
        //		attributes = datasetParser.parseHeaders();
        //		dataOri = datasetParser.parseDataset();
        //		dataAnom = interFace.post(attributes, dataOri);

        //		xmlProperties = loadXmlFile("./datasets/properties5.xml");
        //		document = Functions.readDocument(xmlProperties);
        //		DataOperation interFace = new AnonymizeModule(document);
        //
        //		file = new File("./datasets/boreholes2.txt");
        //		datasetParser = new DatasetParser(file , ";");
        //
        //		attributes = datasetParser.parseHeaders();
        //		dataOri = datasetParser.parseDataset();
        //		dataAnom = interFace.post(attributes, dataOri);

        //		xmlProperties = loadXmlFile("./datasets/properties4.xml");
        //		document = Functions.readDocument(xmlProperties);
        //		DataOperation interFace = new AnonymizeModule(document);
        //
        //		file = new File("./datasets/boreholes2.txt");
        //		datasetParser = new DatasetParser(file , ";");
        //
        //		attributes = datasetParser.parseHeaders();
        //		dataOri = datasetParser.getSingleRecord();
        //		dataAnom = interFace.post(attributes, dataOri);
    }

    public static byte[] loadXmlFile(String filePropertiesName) {
        FileReader2 file;
        String linea;
        String xml;

        file = new FileReader2(filePropertiesName);
        xml = "";
        while ((linea = file.readLine()) != null) {
            xml += linea;
        }
        file.closeFile();
        Functions.readProperties(xml);
        System.out.println("Xml loaded");
        return xml.getBytes();
    }

    public static void saveFile() {
        File file;

        file = new File("./datasets/prova.txt");
        FileWriter fw = null;
        try {
            fw = new FileWriter(file);
            BufferedWriter bw = new BufferedWriter(fw);

            bw.write("prova");
            bw.newLine();
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}