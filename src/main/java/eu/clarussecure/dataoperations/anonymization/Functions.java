package eu.clarussecure.dataoperations.anonymization;

import com.vividsolutions.jts.geom.Geometry;
import com.vividsolutions.jts.geom.GeometryFactory;
import com.vividsolutions.jts.geom.Polygon;
import com.vividsolutions.jts.geom.PrecisionModel;
import com.vividsolutions.jts.io.*;
import eu.clarussecure.dataoperations.AttributeNamesUtilities;
import org.geotools.geometry.jts.GeometryBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Functions {

    // AKKA fix: log
    private static final Logger LOGGER = LoggerFactory.getLogger(Functions.class);

    public static String[][] anonymize(String[] attributes, String[][] content) {
        String[][] dataAnom = null;

        reOrderListsAccordingAttributeParameter(attributes);

        // TODO: Attempt at solving suppression bug
        if (Record.attrTypes.get(Constants.identifier).equalsIgnoreCase(Constants.suppression)) {
            content = suppress(content);
        }

        if (Record.attrTypes.get(Constants.quasiIdentifier).equalsIgnoreCase(Constants.kAnonymity)
                && Record.attrTypes.get(Constants.confidential).equalsIgnoreCase(Constants.tCloseness)) {
            dataAnom = kAnonymize_tCloseness(content, Record.k, Record.t);
            return dataAnom;
        }

        if (Record.attrTypes.get(Constants.quasiIdentifier).equalsIgnoreCase(Constants.kAnonymity)) {
            dataAnom = kAnonymize(content, Record.k);
            return dataAnom;
        }

        if (Record.attrTypes.get(Constants.identifier).equalsIgnoreCase(Constants.coarsening)
                && Record.coarsening_type.equalsIgnoreCase(Constants.shift)) {
            dataAnom = coarseningShift(content, Record.radius);
            return dataAnom;
        }

        if (Record.attrTypes.get(Constants.identifier).equalsIgnoreCase(Constants.coarsening)
                && Record.coarsening_type.equalsIgnoreCase(Constants.microaggregation)) {
            dataAnom = coarseningMicroaggregation(content, Record.k);
            return dataAnom;
        }

        return dataAnom;
    }

    private static void reOrderListsAccordingAttributeParameter(String[] attributes) {
        ArrayList<String> newListNames = new ArrayList<String>();
        // AKKA fix: use pattern for attribute matching
        ArrayList<Pattern> newListNamePatterns = new ArrayList<Pattern>();
        ArrayList<String> newListAttrTypes = new ArrayList<String>();
        ArrayList<String> newListDataTypes = new ArrayList<String>();
        String attr, name;
        boolean ok;

        for (int i = 0; i < attributes.length; i++) {
            attr = attributes[i];
            ok = false;
            // AKKA fix: take refListNames as reference
            for (int j = 0; j < Record.refListNames.size(); j++) {
                name = Record.refListNames.get(j);
                // use pattern for attribute matching
                Pattern pattern = Record.refListNamePatterns.get(j);
                if (pattern.matcher(attr).matches()) {
                    newListNames.add(name);
                    newListNamePatterns.add(Record.refListNamePatterns.get(j));
                    newListAttrTypes.add(Record.refListAttrTypes.get(j));
                    newListDataTypes.add(Record.refListDataTypes.get(j));
                    ok = true;
                    break;
                }
            }
            if (!ok) { // this attribute does not appear in the security policy
                newListNames.add(attr); // it is added as categorical
                                        // non_confidential
                                        // AKKA fix: use pattern for attribute matching
                newListNamePatterns.add(Pattern.compile(AttributeNamesUtilities.escapeRegex(attr)));
                newListAttrTypes.add(Constants.non_confidential);
                newListDataTypes.add(Constants.categoric);
            }
        }
        Record.listNames = newListNames;
        Record.listAttrTypes = newListAttrTypes;
        Record.listDataTypes = newListDataTypes;
        Record.numAttr = newListNames.size();

    }

    /**
     * This function applies k-anonymization to a dataset
     *
     * @param dataOri,
     *            the dataset
     * @param k,
     *            the desired k level
     * @return the anonymized version of the dataset that fullfils k-anonymity
     */

    public static String[][] kAnonymize(String[][] dataOri, int k) {
        ArrayList<Record> data;
        ArrayList<Record> dataAnom;
        String[][] dataAnomStr;

        data = createRecords(dataOri);
        dataAnom = kAnonymize(data, k);
        dataAnomStr = createMatrixStringFromRecords(dataAnom);

        return dataAnomStr;
    }

    public static ArrayList<Record> kAnonymize(ArrayList<Record> dataOri, int k) {
        ArrayList<RecordQ> dataQuasis = new ArrayList<>();
        ArrayList<Record> dataAnom = new ArrayList<>();
        int pos, remain, numReg;
        Cluster cluster;
        RecordQ recordQ;
        Record record;
        String attrType;

        // AKKA fix: log
        LOGGER.trace("Anonymizing kAnonymity k = {}...", k);

        RecordQ.numAttr = Record.numQuasi;
        RecordQ.listAttrTypes = new ArrayList<String>();
        RecordQ.listDataTypes = new ArrayList<String>();
        for (int i = 0; i < Record.numAttr; i++) {
            attrType = Record.listAttrTypes.get(i);
            if (attrType.equalsIgnoreCase(Constants.quasiIdentifier)) {
                RecordQ.listAttrTypes.add(Record.listAttrTypes.get(i));
                RecordQ.listDataTypes.add(Record.listDataTypes.get(i));
            }
        }
        for (Record reg : dataOri) { // create records with quasi-identifiers
            dataQuasis.add(reg.toRecordQ());
        }

        Distances.calculateTypicalDeviationsNumeric(dataQuasis);
        // AKKA fix: log
        LOGGER.debug("Sorting by quasi-identifiers done");
        Functions.sortByQuasi(dataQuasis);
        System.out.println("done");

        // AKKA fix: log
        LOGGER.trace("Anonymizing...");

        cluster = new Cluster();
        numReg = dataQuasis.size();
        pos = 0;
        remain = numReg;
        while (remain >= (2 * k)) {
            for (int i = 0; i < k; i++) {
                cluster.add(dataQuasis.get(pos));
                pos++;
            }
            cluster.calculateCentroid();
            pos -= k;
            for (int i = 0; i < k; i++) {
                for (int j = 0; j < RecordQ.numAttr; j++) {
                    dataQuasis.get(pos).attrValues[j] = cluster.getCentroid().attrValues[j];
                }
                pos++;
            }
            cluster.clear();
            remain = numReg - pos;
        }
        for (int i = 0; i < remain; i++) {
            cluster.add(dataQuasis.get(pos));
            pos++;
        }
        cluster.calculateCentroid();
        pos -= remain;
        for (int i = 0; i < remain; i++) {
            for (int j = 0; j < RecordQ.numAttr; j++) {
                dataQuasis.get(pos).attrValues[j] = cluster.getCentroid().attrValues[j];
            }
            pos++;
        }

        // AKKA fix: log
        LOGGER.debug("Anonymizing done...");

        // AKKA fix: log
        LOGGER.trace("Rearranging...");
        Collections.sort(dataQuasis, new ComparatorID());
        for (int i = 0; i < dataQuasis.size(); i++) { // anonymize original data
            recordQ = dataQuasis.get(i);
            record = dataOri.get(i).clone();
            dataAnom.add(recordQ.toRecord(record));
        }
        // AKKA fix: log
        LOGGER.debug("Rearranging done...");

        // AKKA fix: log
        LOGGER.debug("Anonymizing done (kAnonymity k = {})", k);

        return dataAnom;
    }

    /**
     * This function applies k-anonymization + t-closeness to a dataset
     *
     * @param dataOri,
     *            the dataset
     * @param k,
     *            the desired k level
     * @param t,
     *            the desired t closeness
     * @return the anonymized version of the dataset that fullfils k-anonymity
     *         and t-closeness
     */

    public static String[][] kAnonymize_tCloseness(String[][] dataOri, int k, double t) {
        ArrayList<Record> data;
        ArrayList<Record> dataAnom;
        String[][] dataAnomStr;

        data = createRecords(dataOri);
        dataAnom = kAnonymize_tCloseness(data, k, t);
        dataAnomStr = createMatrixStringFromRecords(dataAnom);

        return dataAnomStr;
    }

    public static ArrayList<Record> kAnonymize_tCloseness(ArrayList<Record> dataOri, int k, double t) {
        ArrayList<RecordQ> dataQuasis = new ArrayList<>();
        ArrayList<Record> dataAnom = new ArrayList<>();
        ArrayList<Cluster> clustersK = new ArrayList<Cluster>();
        ArrayList<Cluster> clusters = new ArrayList<Cluster>();
        RecordQ r;
        int n;
        int remain, numAttrQuasi, attrSensitive;
        int numItem, index, numClustersK, remainder;
        double kPrime;
        Cluster clusterTemp;
        RecordQ recordQ;
        String attrType;

        // AKKA fix: log
        LOGGER.trace("Anonymizing kAnonymity / tCloseness k = {} / t = {}...", k, t);

        RecordQ.numAttr = Record.numQuasi + 1;
        RecordQ.listAttrTypes = new ArrayList<String>();
        RecordQ.listDataTypes = new ArrayList<String>();
        for (int i = 0; i < Record.numAttr; i++) {
            attrType = Record.listAttrTypes.get(i);
            if (attrType.equalsIgnoreCase(Constants.quasiIdentifier)) {
                RecordQ.listAttrTypes.add(Record.listAttrTypes.get(i));
                RecordQ.listDataTypes.add(Record.listDataTypes.get(i));
            }
        }
        for (int i = 0; i < Record.numAttr; i++) {
            attrType = Record.listAttrTypes.get(i);
            if (attrType.equalsIgnoreCase(Constants.confidential)) {
                RecordQ.listAttrTypes.add(Record.listAttrTypes.get(i));
                RecordQ.listDataTypes.add(Record.listDataTypes.get(i));
            }
        }
        for (Record reg : dataOri) { // crea records con solo los quasi + 1
                                         // sensible
            dataQuasis.add(reg.toRecordQConfidential());
        }

        Distances.calculateTypicalDeviationsNumericWithConfidential(dataQuasis);
        // AKKA fix: log
        LOGGER.trace("Sorting by confidential attribute...");
        attrSensitive = dataQuasis.get(0).attrValues.length - 1;
        Functions.sortBySensitive(dataQuasis, attrSensitive);
        // AKKA fix: log
        LOGGER.debug("Sorting by confidential attribute done");

        n = dataQuasis.size();
        kPrime = n / (2 * (n - 1) * t + 1);
        if (k > kPrime) {
            numClustersK = k;
        } else {
            numClustersK = ((int) kPrime) + 1;
        }
        numItem = dataQuasis.size() / numClustersK;
        remainder = dataQuasis.size() % numClustersK;

        if (remainder >= numItem) {
            numClustersK = numClustersK + (remainder / numItem);
        }

        // AKKA fix: log
        LOGGER.trace("Creating k subsets({})...", numClustersK);
        index = 0;
        for (int i = 0; i < numClustersK; i++) {
            clusterTemp = new Cluster();
            for (int j = 0; j < numItem; j++) {
                r = dataQuasis.get(index);
                clusterTemp.add(r);
                index++;
            }
            clustersK.add(clusterTemp);
        }

        if (index < dataQuasis.size()) { // remain records in a cluster
            clusterTemp = new Cluster();
            for (int i = index; i < dataQuasis.size(); i++) {
                r = dataQuasis.get(i);
                clusterTemp.add(r);
            }
            clustersK.add(clusterTemp);
        }
        // AKKA fix: log
        LOGGER.debug("Creating k subsets({}) done", numClustersK);

        // AKKA fix: log
        LOGGER.trace("Sorting by quasi-identifier attributes each subset...");
        for (Cluster cluster : clustersK) {
            Functions.sortByQuasi(cluster.getElements());
        }
        // AKKA fix: log
        LOGGER.debug("Sorting by quasi-identifier attributes each subset done");

        // AKKA fix: log
        LOGGER.trace("Creating clusters...");
        remain = dataQuasis.size();
        dataQuasis.clear();
        index = 0;
        while (remain > 0) {
            clusterTemp = new Cluster();
            for (Cluster cluster : clustersK) {
                if (cluster.getElements().size() > index) {
                    clusterTemp.add(cluster.getElements().get(index)); // the
                                                                       // next
                                                                       // record
                                                                       // is
                                                                       // added
                    remain--;
                }
            }
            index++;
            clusters.add(clusterTemp);
        }
        // AKKA fix: log
        LOGGER.debug("Creating clusters done");

        // AKKA fix: log
        LOGGER.trace("Anonymizing...");
        numAttrQuasi = clusters.get(0).getElements().get(0).attrValues.length - 1;
        for (Cluster cluster : clusters) {
            cluster.calculateCentroid();
            for (RecordQ reg : cluster.getElements()) {
                for (int j = 0; j < numAttrQuasi; j++) {
                    reg.attrValues[j] = cluster.getCentroid().attrValues[j];
                }
                dataQuasis.add(reg);
            }
        }
        // AKKA fix: log
        LOGGER.debug("Anonymizing done");

        // AKKA fix: log
        LOGGER.trace("ReArranging...");
        Collections.sort(dataQuasis, new ComparatorID());
        for (int i = 0; i < dataQuasis.size(); i++) {
            recordQ = dataQuasis.get(i);
            dataAnom.add(recordQ.toRecord(dataOri.get(i)));
        }
        // AKKA fix: log
        LOGGER.debug("ReArranging done");

        // AKKA fix: log
        LOGGER.debug("Anonymizing done (kAnonymity / tCloseness k = {} / t = {})", k, t);

        return dataAnom;
    }

    /**
     * This function applies coarsening shift to a dataset
     *
     * @param dataOri,
     *            the dataset
     * @param radius,
     *            the desired level of privacy (radius of circle)
     * @return the anonymized version of the dataset that fullfils k-anonymity
     */

    public static String[][] coarseningShift(String[][] dataOri, double radius) {
        ArrayList<Record> data;
        ArrayList<Record> dataAnom;
        String[][] dataAnomStr;

        data = createRecords(dataOri);
        dataAnom = coarseningShift(data, radius);
        dataAnomStr = createMatrixStringFromRecords(dataAnom);

        return dataAnomStr;
    }

    public static ArrayList<Record> coarseningShift(ArrayList<Record> dataOri, double radius) {
        ArrayList<Record> dataAnom = new ArrayList<Record>();
        ArrayList<String> geometricObjects = new ArrayList<String>();
        ArrayList<String> geometricObjectsAnom = new ArrayList<String>();
        int posGeom;
        String attrType, dataType, geomStr;
        Geometry geom; // Objecte geometric basic
        // AKKA fix: use WKT
        WKBReader wkbReader = new WKBReader(); // Parseja objectes en format WKB
                                               // (Well Known Binary)
        WKBWriter wkbWriter = new WKBWriter(2, true); // Converteix objectes de
                                                      // GeoTools
        WKTReader wktReader = new WKTReader(); // Parseja objectes en format WKT
                                               // (Well Known Text)
        WKTWriter wktWriter = new WKTWriter(2); // Converteix objectes de
                                                // GeoTools en format WKT (Well
                                                // Known Text)
        Geometry cir;
        double x, y;
        Circle circle;
        Record record, recordAnom;

        // AKKA fix: log
        LOGGER.trace("Coarsening radius = {}...", radius);
        posGeom = 0;
        for (int i = 0; i < Record.numAttr; i++) { // posicio del
                                                       // geometric_object
            attrType = Record.listAttrTypes.get(i);
            if (attrType.equalsIgnoreCase(Constants.identifier)) {
                dataType = Record.listDataTypes.get(i);
                if (dataType.equalsIgnoreCase(Constants.geometricObject)) {
                    posGeom = i;
                    break;
                }
            }
        }

        for (Record reg : dataOri) {
            geomStr = reg.attrValues[posGeom];
            geometricObjects.add(geomStr);
        }
        for (String s : geometricObjects) { // extreu i converteix coordenada a
                                                // cercle

            // AKKA fix: first, try to read geom in WKT format, the nin WKB
            boolean wktFormat = true;
            boolean withSRID = false;
            geom = null;
            try {
                int srid = 0;
                String wkt = s;
                withSRID = wkt.startsWith("SRID");
                if (withSRID) {
                    int begin = wkt.indexOf('=') + 1;
                    int end = wkt.indexOf(';', begin);
                    srid = Integer.parseInt(wkt.substring(begin, end));
                    wkt = wkt.substring(end + 1);
                }
                geom = wktReader.read(wkt);
                geom.setSRID(srid);
            } catch (ParseException e) {
                wktFormat = false;
                try {
                    geom = wkbReader.read(WKBReader.hexToBytes(s));
                } catch (ParseException e2) {
                    e.printStackTrace();
                }
            }
            if (geom != null) {
                x = geom.getCoordinate().x;
                y = geom.getCoordinate().y;
                circle = shift(x, y, radius);
                // radius unit and value depends on SRID.
                cir = create3DCircle(circle.centre.latitude, circle.centre.longitude, radius);
                // preserve SRID
                cir.setSRID(geom.getSRID());
                // write geom in same format (WKT or WKB)
                if (wktFormat) {
                    s = wktWriter.write(cir);
                    if (withSRID) {
                        s = "SRID=" + cir.getSRID() + ";" + s;
                    }
                } else {
                    s = WKBWriter.toHex(wkbWriter.write(cir));
                }
                geometricObjectsAnom.add(s);
            }
        }
        for (int i = 0; i < dataOri.size(); i++) {
            record = dataOri.get(i);
            recordAnom = record.clone();
            recordAnom.attrValues[posGeom] = geometricObjectsAnom.get(i);
            dataAnom.add(recordAnom);
        }
        // AKKA fix: log
        LOGGER.debug("Coarsening done (radius = {})", radius);

        return dataAnom;
    }

    // TODO: Fix suppression bug
    public static String[][] suppress(String[][] dataOri) {
        ArrayList<Record> data;
        ArrayList<Record> dataAnom;
        String[][] dataAnomStr;

        data = createRecords(dataOri);
        dataAnom = suppression(data);
        dataAnomStr = createMatrixStringFromRecords(dataAnom);

        return dataAnomStr;
    }

    // TODO: fix suppression bug
    public static ArrayList<Record> suppression(ArrayList<Record> dataOri) {

        LOGGER.trace("Suppressing...");
        for (int i = 0; i < Record.numAttr; i++) {
            if (Record.listAttrTypes.get(i).equalsIgnoreCase(Constants.identifier)) {
                for (Record r : dataOri) {
                    r.attrValues[i] = "*****";
                }
            }
        }

        return dataOri;
    }

    /**
     * This function applies coarsening microaggregation to a dataset
     *
     * @param dataOri,
     *            the dataset
     * @param k,
     *            the desired level of privacy
     * @return the anonymized version of the dataset that fullfils k-anonymity
     */

    public static String[][] coarseningMicroaggregation(String[][] dataOri, int k) {
        ArrayList<Record> data;
        ArrayList<Record> dataAnom;
        String[][] dataAnomStr;

        data = createRecords(dataOri);
        dataAnom = coarseningMicroaggregation(data, k);
        dataAnomStr = createMatrixStringFromRecords(dataAnom);

        return dataAnomStr;
    }

    public static ArrayList<Record> coarseningMicroaggregation(ArrayList<Record> dataOri, int k) {
        ArrayList<Record> dataAnom = new ArrayList<Record>();
        ArrayList<String> geometricObjectsAnom = new ArrayList<String>();
        ArrayList<CoordinateS> pointsAnom = new ArrayList<CoordinateS>();
        ArrayList<Circle> circles = new ArrayList<Circle>();
        ArrayList<ClusterPoints> clusters = new ArrayList<ClusterPoints>();
        CoordinateS centroid, farthest, closest;
        ClusterPoints cluster;
        double distance;
        Circle circle;
        int posGeom;
        String attrType, dataType, geomStr;
        Geometry geom; // Objecte geometric basic
        // AKKA fix: use WKT
        WKBReader wkbReader = new WKBReader(); // Parseja objectes en format WKB
                                               // (Well Known Binary)
        WKBWriter wkbWriter = new WKBWriter(2, true); // Converteix objectes de
                                                      // GeoTools
        WKTReader wktReader = new WKTReader(); // Parseja objectes en format WKT
                                               // (Well Known Text)
        WKTWriter wktWriter = new WKTWriter(2); // Converteix objectes de
                                                // GeoTools en format WKT (Well
                                                // Known Text)
        Geometry cir;
        double x, y;
        Record record, recordAnom;

        // AKKA fix: log
        LOGGER.trace("Coarsening microaggregation k = {}...", k);

        posGeom = 0;
        for (int i = 0; i < Record.numAttr; i++) { // posicio del
                                                       // geometric_object
            attrType = Record.listAttrTypes.get(i);
            if (attrType.equalsIgnoreCase(Constants.identifier)) {
                dataType = Record.listDataTypes.get(i);
                if (dataType.equalsIgnoreCase(Constants.geometricObject)) {
                    posGeom = i;
                    break;
                }
            }
        }
        // AKKA fix: first, try to read geom in WKT format, the nin WKB format
        boolean wktFormat = true;
        boolean withSRID = false;
        for (Record reg : dataOri) {
            geomStr = reg.attrValues[posGeom];
            geom = null;
            try {
                int srid = 0;
                String wkt = geomStr;
                withSRID = wkt.startsWith("SRID");
                if (withSRID) {
                    int begin = wkt.indexOf('=') + 1;
                    int end = wkt.indexOf(';', begin);
                    srid = Integer.parseInt(wkt.substring(begin, end));
                    wkt = wkt.substring(end + 1);
                }
                geom = wktReader.read(wkt);
                geom.setSRID(srid);
            } catch (ParseException e) {
                wktFormat = false;
                try {
                    geom = wkbReader.read(WKBReader.hexToBytes(geomStr));
                } catch (ParseException e2) {
                    e.printStackTrace();
                }
            }
            if (geom != null) {
                x = geom.getCoordinate().x;
                y = geom.getCoordinate().y;
                // preserve SRID
                pointsAnom.add(new CoordinateS(y, x, reg.id, geom.getSRID()));
            }
        }

        while (pointsAnom.size() >= k) {
            centroid = calculateCentroid(pointsAnom);
            farthest = calculateFarthestPoint(centroid, pointsAnom);
            cluster = new ClusterPoints();
            cluster.add(farthest);
            pointsAnom.remove(farthest);
            centroid = cluster.calculateCentroid();
            while (cluster.getNumPoints() < k) {
                closest = calculateClosestPoint(centroid, pointsAnom);
                cluster.add(closest);
                pointsAnom.remove(closest);
                centroid = cluster.calculateCentroid();
            }
            clusters.add(cluster);
        }
        for (CoordinateS p : pointsAnom) { // remaining points to its closest
                                               // cluster
            cluster = calculateClosestCluster(p, clusters);
            cluster.add(p);
            cluster.calculateCentroid();
        }
        for (ClusterPoints c : clusters) { // calculates radius circle (max
                                               // distance to centroid)
            centroid = c.getCentroid();
            farthest = calculateFarthestPoint(centroid, c.getPoints());
            // AKKA fix: centroid.distanceSq returns square of distance, so take
            // the square root
            distance = Math.sqrt(centroid.distanceSq(farthest));
            for (CoordinateS coo : c.getPoints()) { // each point of cluster has
                                                        // the same coordinates
                circle = new Circle(centroid, distance);
                circle.centre.id = coo.id;
                // AKKA fix: save SRID of original Point
                circle.centre.srid = coo.srid;
                circles.add(circle);
            }
        }
        Collections.sort(circles, new ComparatorIdCircles());

        for (Circle c : circles) {
            // AKKA fix: radius unit depends on SRID. Don't convert it
            // cir = create3DCircle(c.centre.latitude, c.centre.longitude,
            // (c.radius/1852));
            cir = create3DCircle(c.centre.latitude, c.centre.longitude, c.radius);
            // AKKA fix: SRID of Polygon must be the same than SRID of original
            // Point
            //// AKKA fix: inverse latitude and longitude
            //// cir.setSRID(calculateSrid(c.centre.latitude,
            // c.centre.longitude, 4326));
            cir.setSRID(c.centre.srid);
            // AKKA fix: write geom in same format (WKT or WKB)
            if (wktFormat) {
                geomStr = wktWriter.write(cir);
                if (withSRID) {
                    geomStr = "SRID=" + cir.getSRID() + ";" + geomStr;
                }
            } else {
                geomStr = WKBWriter.toHex(wkbWriter.write(cir));
            }
            geometricObjectsAnom.add(geomStr);
        }

        for (int i = 0; i < dataOri.size(); i++) {
            record = dataOri.get(i);
            recordAnom = record.clone();
            recordAnom.attrValues[posGeom] = geometricObjectsAnom.get(i);
            dataAnom.add(recordAnom);
        }
        // AKKA fix: log
        LOGGER.debug("Coarsening microaggregation done (k = {})", k);

        return dataAnom;
    }

    private static ClusterPoints calculateClosestCluster(CoordinateS point, ArrayList<ClusterPoints> clusters) {
        ClusterPoints closest;
        double minDistance, distance;

        closest = null;
        minDistance = Double.MAX_VALUE;
        for (ClusterPoints c : clusters) {
            distance = c.getCentroid().distanceSq(point);
            if (distance < minDistance) {
                closest = c;
                minDistance = distance;
            }
        }

        return closest;
    }

    private static CoordinateS calculateClosestPoint(CoordinateS point, ArrayList<CoordinateS> points) {
        CoordinateS closest;
        double minDistance, distance;

        closest = null;
        minDistance = Double.MAX_VALUE;
        for (CoordinateS p : points) {
            distance = p.distanceSq(point);
            if (distance < minDistance) {
                closest = p;
                minDistance = distance;
            }
        }

        return closest;
    }

    private static CoordinateS calculateFarthestPoint(CoordinateS point, ArrayList<CoordinateS> points) {
        CoordinateS farthest;
        double maxDistance, distance;

        farthest = null;
        maxDistance = 0;
        for (CoordinateS p : points) {
            distance = p.distanceSq(point);
            if (distance > maxDistance) {
                farthest = p;
                maxDistance = distance;
            }
        }

        return farthest;
    }

    private static CoordinateS calculateCentroid(ArrayList<CoordinateS> points) {
        CoordinateS centroid;
        double maxX, maxY, minX, minY;
        double x, y;

        maxX = maxY = -Double.MAX_VALUE;
        minX = minY = Double.MAX_VALUE;
        centroid = new CoordinateS(maxX, maxY);
        for (CoordinateS p : points) {
            x = p.latitude;
            y = p.longitude;
            if (x > maxX) {
                maxX = x;
            }
            if (y > maxY) {
                maxY = y;
            }
            if (x < minX) {
                minX = x;
            }
            if (y < minY) {
                minY = y;
            }
        }
        x = (maxX + minX) / 2;
        y = (maxY + minY) / 2;
        centroid.setLocation(x, y);

        return centroid;
    }

    public static int calculateSrid(double x, double y, int srid) {
        int pref;
        int zone;

        if (y > 0)
            pref = 32600;
        else
            pref = 32700;

        zone = ((int) ((x + 180) / 6)) + 1; // Casting a double to int behaves
                                            // as we want (Drops the decimals)

        return zone + pref;
    }

    // AKKA fix: inverse latitude and longitude
    // private static Geometry create3DCircle(double lng, double lat, double
    // radiusNm) {
    private static Geometry create3DCircle(double lat, double lng, double radius) {
        PrecisionModel pmodel = new PrecisionModel(); // No podem especificar un
                                                      // SRID al GeometryFactory
                                                      // sense passarli un
                                                      // PrecisionModel

        // AKKA fix: don't need SRID here
        GeometryFactory builder = new GeometryFactory(pmodel); // GeometryFactory
                                                               // crea objectes
                                                               // geometrics de
                                                               // gis

        // AKKA fix: use GeometryBuilder.circle() to create the polygon
        GeometryBuilder gb = new GeometryBuilder(builder);
        final int SIDES = 32 + 16 * new Random().nextInt(4); // Random.
        Polygon polygon = gb.circle(lng, lat, radius, SIDES);
        return polygon;
    }

    // AKKA fix: radius unit depends on SRID. Don't convert it
    // public static Circle shift(double x1, double y1, int metersPrivacy) {
    // return shift(x1, y1, (double)metersPrivacy/111220); //111220 metres per
    // grau
    // }

    public static Circle shift(double x1, double y1, double privacy) {
        double theta = ThreadLocalRandom.current().nextDouble((360 - 0) + 1);
        double x2 = x1 + (Math.cos(theta) * privacy);
        double y2 = y1 + (Math.sin(theta) * privacy);

        // System.out.println(theta);
        // System.out.println("cos(theta) = "+Math.cos(Math.toRadians(theta)));
        // System.out.println("sin(theta) = "+Math.sin(Math.toRadians(theta)) );

        // System.out.println(eu.clarussecure.dataoperations.anonymization.Distances.distanciaHaversine(x1,
        // y1, x2, y2));

        // System.out.println("max distance: "+x2+" "+y2);

        double x = x1 + ((x2 - x1) * ThreadLocalRandom.current().nextDouble());
        double y = y1 + ((y2 - y1) * ThreadLocalRandom.current().nextDouble());

        // System.out.println(y+", "+x); //prints in google maps style (latitude
        // and longitude)

        return new Circle(x, y, privacy);
    }

    private static void sortByQuasi(ArrayList<RecordQ> data) {

        ComparatorQuasi.setAttributeSortCriteria(data.get(0));
        Collections.sort(data, new ComparatorQuasi());
    }

    private static void sortBySensitive(ArrayList<RecordQ> data, int attr) {
        ComparatorSensitive.setAttributeSortCriteria(attr);
        Collections.sort(data, new ComparatorSensitive());
    }

    public static void readPropertiesFromFile(String fileProperties) {
        Document document;

        document = readDocumentFromFile(fileProperties);
        readProperties(document);
    }

    public static void readProperties(String xml) {
        Document document;

        document = readDocument(xml);
        readProperties(document);
    }

    public static void readProperties(byte[] xml) {
        Document document;

        document = readDocument(xml);
        readProperties(document);
    }

    private static Document readDocumentFromFile(String fileProperties) {
        Document document = null;

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            document = db.parse(new File(fileProperties));
            document.getDocumentElement().normalize();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return document;
    }

    private static Document readDocument(String xml) {
        Document document = null;

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            InputSource is = new InputSource(new StringReader(xml));
            document = db.parse(is);
            document.getDocumentElement().normalize();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return document;
    }

    public static Document readDocument(byte[] xml) {
        Document document = null;

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            InputSource is = new InputSource(new StringReader(new String(xml)));
            document = db.parse(is);
            document.getDocumentElement().normalize();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return document;
    }

    public static void readProperties(Document document) {
        int numQuasis;

        // URV fix: removed header, attribute_separator and record_separator
        // URV fix: elements are retrieved by their name

        Record.attrTypes = getAttributeTypes(document);
        for (String s : Record.attrTypes.values()) {
            if (s.equalsIgnoreCase(Constants.kAnonymity)) {
                Record.k = Integer.parseInt(getK(document));
            }
            if (s.equalsIgnoreCase(Constants.tCloseness)) {
                Record.t = Double.parseDouble(getT(document));
            }
            if (s.equalsIgnoreCase(Constants.splitting)) {
                Record.clouds = Integer.parseInt(getClouds(document));
            }
            if (s.equalsIgnoreCase(Constants.encryption)) {
                Record.idKey = getIdKey(document);
            }
            if (s.equalsIgnoreCase(Constants.coarsening)) {
                Record.coarsening_type = getCoarseningType(document);
                if (Record.coarsening_type.equalsIgnoreCase(Constants.shift)) {
                    // AKKA fix: radius value depends on SRID. it could be a
                    // real
                    // Record.radius = Integer.parseInt(getRadius(document));
                    Record.radius = Double.parseDouble(getRadius(document));
                }
                if (Record.coarsening_type.equalsIgnoreCase(Constants.microaggregation)) {
                    Record.k = Integer.parseInt(getCoarseningK(document));
                }
            }
        }
        // AKKA fix: replace unqualified attribute name by a generic qualified
        // one (with asterisks).
        // Moreover, save resolved attribute names and types in refListNames,
        // refListNamePatterns and refListAttrTypes
        List<String> attributeNames = getAtributeNames(document);
        attributeNames = AttributeNamesUtilities.fullyQualified(attributeNames);
        List<Pattern> attributePatterns = attributeNames.stream().map(AttributeNamesUtilities::escapeRegex)
                .map(Pattern::compile).collect(Collectors.toList());
        Record.refListNames = Record.listNames = (ArrayList<String>) attributeNames;
        Record.refListNamePatterns = Record.listNamePatterns = (ArrayList<Pattern>) attributePatterns;
        Record.refListAttrTypes = Record.listAttrTypes = getAtributeTypes(document);
        numQuasis = 0;
        for (String s : Record.listAttrTypes) {
            if (s.equals(Constants.quasiIdentifier)) {
                numQuasis++;
            }
        }
        Record.numQuasi = numQuasis;
        if (Record.numQuasi == 0) {
            Record.attrTypes.put(Constants.quasiIdentifier, "null");
        }
        // AKKA fix: save resolved data types and attribute number in
        // refListDataTypes and refNumAttr
        Record.refListDataTypes = Record.listDataTypes = getAttributeDataTypes(document);
        Record.refNumAttr = Record.numAttr = Record.listAttrTypes.size();
    }

    private static HashMap<String, String> getAttributeTypes(Document document) {
        HashMap<String, String> attrTypes = new HashMap<String, String>();
        Node node;
        NamedNodeMap attributes;
        String type, protection;
        NodeList nodeList;

        // URV fix: elements are retrieved by their name
        nodeList = document.getElementsByTagName(Constants.attributeType);

        for (int i = 0; i < nodeList.getLength(); i++) {
            node = nodeList.item(i);
            attributes = node.getAttributes();
            node = attributes.getNamedItem(Constants.type);
            type = node.getNodeValue();
            node = attributes.getNamedItem(Constants.protection);
            protection = node.getNodeValue();
            attrTypes.put(type, protection);
        }

        return attrTypes;
    }

    private static String getK(Document document) {
        Node node;
        NamedNodeMap attributes;
        String protection;
        String k = null;
        NodeList nodeList;

        // URV fix: elements are retrieved by their name
        nodeList = document.getElementsByTagName(Constants.attributeType);

        for (int i = 0; i < nodeList.getLength(); i++) {
            node = nodeList.item(i);
            attributes = node.getAttributes();
            node = attributes.getNamedItem(Constants.protection);
            protection = node.getNodeValue();
            if (protection.equalsIgnoreCase(Constants.kAnonymity)) {
                node = attributes.getNamedItem(Constants.k);
                k = node.getNodeValue();
                break;
            }
        }

        return k;
    }

    private static String getT(Document document) {
        Node node;
        NamedNodeMap attributes;
        String protection;
        String t = null;
        NodeList nodeList;

        // URV fix: elements are retrieved by their name
        nodeList = document.getElementsByTagName(Constants.attributeType);

        for (int i = 0; i < nodeList.getLength(); i++) {
            node = nodeList.item(i);
            attributes = node.getAttributes();
            node = attributes.getNamedItem(Constants.protection);
            protection = node.getNodeValue();
            if (protection.equalsIgnoreCase(Constants.tCloseness)) {
                node = attributes.getNamedItem(Constants.t);
                t = node.getNodeValue();
                break;
            }
        }

        return t;
    }

    private static String getClouds(Document document) {
        Node node;
        NamedNodeMap attributes;
        String protection;
        String clouds = null;
        NodeList nodeList;

        // URV fix: elements are retrieved by their name
        nodeList = document.getElementsByTagName(Constants.attributeType);

        for (int i = 0; i < nodeList.getLength(); i++) {
            node = nodeList.item(i);
            attributes = node.getAttributes();
            node = attributes.getNamedItem(Constants.protection);
            protection = node.getNodeValue();
            if (protection.equalsIgnoreCase(Constants.splitting)) {
                node = attributes.getNamedItem(Constants.clouds);
                clouds = node.getNodeValue();
                break;
            }
        }

        return clouds;
    }

    private static String getIdKey(Document document) {
        Node node;
        NamedNodeMap attributes;
        String protection;
        String idKey = null;
        NodeList nodeList;

        // URV fix: elements are retrieved by their name
        nodeList = document.getElementsByTagName(Constants.attributeType);

        for (int i = 0; i < nodeList.getLength(); i++) {
            node = nodeList.item(i);
            attributes = node.getAttributes();
            node = attributes.getNamedItem(Constants.protection);
            protection = node.getNodeValue();
            if (protection.equalsIgnoreCase(Constants.encryption)) {
                node = attributes.getNamedItem(Constants.id_key);
                idKey = node.getNodeValue();
                break;
            }
        }

        return idKey;
    }

    private static String getRadius(Document document) {
        Node node;
        NamedNodeMap attributes;
        String protection;
        String radius = null;
        NodeList nodeList;

        // URV fix: elements are retrieved by their name
        nodeList = document.getElementsByTagName(Constants.attributeType);

        for (int i = 0; i < nodeList.getLength(); i++) {
            node = nodeList.item(i);
            attributes = node.getAttributes();
            node = attributes.getNamedItem(Constants.protection);
            protection = node.getNodeValue();
            if (protection.equalsIgnoreCase(Constants.coarsening)) {
                node = attributes.getNamedItem(Constants.radius);
                radius = node.getNodeValue();
                break;
            }
        }

        return radius;
    }

    private static String getCoarseningType(Document document) {
        Node node;
        NamedNodeMap attributes;
        String protection;
        String type = null;
        NodeList nodeList;

        // URV fix: elements are retrieved by their name
        nodeList = document.getElementsByTagName(Constants.attributeType);

        for (int i = 0; i < nodeList.getLength(); i++) {
            node = nodeList.item(i);
            attributes = node.getAttributes();
            node = attributes.getNamedItem(Constants.protection);
            protection = node.getNodeValue();
            if (protection.equalsIgnoreCase(Constants.coarsening)) {
                node = attributes.getNamedItem(Constants.coarseningType);
                type = node.getNodeValue();
                break;
            }
        }

        return type;
    }

    private static String getCoarseningK(Document document) {
        Node node;
        NamedNodeMap attributes;
        String protection;
        String k = null;
        NodeList nodeList;

        // URV fix: elements are retrieved by their name
        nodeList = document.getElementsByTagName(Constants.attributeType);

        for (int i = 0; i < nodeList.getLength(); i++) {
            node = nodeList.item(i);
            attributes = node.getAttributes();
            node = attributes.getNamedItem(Constants.protection);
            protection = node.getNodeValue();
            if (protection.equalsIgnoreCase(Constants.coarsening)) {
                node = attributes.getNamedItem(Constants.k);
                k = node.getNodeValue();
                break;
            }
        }

        return k;
    }

    private static ArrayList<String> getAtributeNames(Document document) {
        ArrayList<String> names = new ArrayList<String>();
        Node node;
        NamedNodeMap attributes;
        String name;
        NodeList nodeList;

        // URV fix: elements are retrieved by their name
        nodeList = document.getElementsByTagName(Constants.attribute);

        for (int i = 0; i < nodeList.getLength(); i++) {
            node = nodeList.item(i);
            attributes = node.getAttributes();
            node = attributes.getNamedItem(Constants.name);
            name = node.getNodeValue();
            names.add(name);
        }

        return names;
    }

    private static ArrayList<String> getAtributeTypes(Document document) {
        ArrayList<String> attrTypes = new ArrayList<String>();
        Node node;
        NamedNodeMap attributes;
        String attrType;
        NodeList nodeList;

        // URV fix: elements are retrieved by their name
        nodeList = document.getElementsByTagName(Constants.attribute);

        for (int i = 0; i < nodeList.getLength(); i++) {
            node = nodeList.item(i);
            attributes = node.getAttributes();
            node = attributes.getNamedItem(Constants.attributeType);
            attrType = node.getNodeValue();
            attrTypes.add(attrType);
        }

        return attrTypes;
    }

    private static ArrayList<String> getAttributeDataTypes(Document document) {
        ArrayList<String> attrTypes = new ArrayList<String>();
        Node node;
        NamedNodeMap attributes;
        String attrType;
        NodeList nodeList;

        // URV fix: elements are retrieved by their name
        nodeList = document.getElementsByTagName(Constants.attribute);

        for (int i = 0; i < nodeList.getLength(); i++) {
            node = nodeList.item(i);
            attributes = node.getAttributes();
            node = attributes.getNamedItem(Constants.dataType);
            if (node == null) {
                attrTypes.add("");
            } else {
                attrType = node.getNodeValue();
                attrTypes.add(attrType);
            }
        }

        return attrTypes;
    }

    public static ArrayList<Record> createRecords(String data) {
        // AKKA fix: log
        LOGGER.trace("Loading records...");

        ArrayList<Record> records = new ArrayList<Record>();
        String recordsStr[];
        String strTemp[];
        Record record;
        int id;

        recordsStr = data.split(Record.recordSeparator);
        id = 0;
        for (int i = 0; i < recordsStr.length; i++) {
            strTemp = recordsStr[i].split(Record.attributeSeparator);
            record = new Record(id);
            id++;
            for (int j = 0; j < Record.numAttr; j++) {
                record.attrValues[j] = strTemp[j];
            }
            records.add(record);
        }

        // AKKA fix: log
        LOGGER.debug("Records loaded: {}", records.size());
        return records;
    }

    public static ArrayList<Record> createRecords(String[][] data) {
        // AKKA fix: log
        LOGGER.trace("Loading records...");

        ArrayList<Record> records = new ArrayList<Record>();
        Record record = null;
        int id;

        id = 0;
        for (int i = 0; i < data.length; i++) {
            record = new Record(id);
            id++;
            for (int j = 0; j < data[i].length; j++) {
                record.attrValues[j] = data[i][j];
            }
            records.add(record);
        }

        // AKKA fix: log
        LOGGER.debug("Records loaded: {}", records.size());
        return records;
    }

    public static String[][] createMatrixStringFromRecords(ArrayList<Record> records) {
        // AKKA fix: log
        LOGGER.trace("Converting {} records to String matrix", records.size());

        String data[][];
        Record record;

        data = new String[records.size()][];
        for (int i = 0; i < records.size(); i++) {
            record = records.get(i);
            data[i] = record.toVectorString();
        }

        // AKKA fix: log
        LOGGER.debug("{} records converted to String matrix", data.length);
        return data;
    }

    public static ArrayList<Record> readFile(String fileStr, String fileProperties) {
        // AKKA fix: log
        LOGGER.trace("Loading records...");

        ArrayList<Record> records = new ArrayList<Record>();
        FileReader2 file;
        String linea;
        String strTemp[];
        Record record;
        int id;

        readPropertiesFromFile(fileProperties);
        file = new FileReader2(fileStr);
        if (Record.header) {
            linea = file.readLine();
        }
        id = 0;
        while ((linea = file.readLine()) != null) {
            strTemp = linea.split(Record.attributeSeparator);
            record = new Record(id);
            id++;
            for (int i = 0; i < Record.numAttr; i++) {
                record.attrValues[i] = strTemp[i];
            }
            records.add(record);
        }
        file.closeFile();
        // AKKA fix: log
        LOGGER.debug("Records loaded: {}", records.size());
        return records;
    }

    @Deprecated
    public static void writeFile(ArrayList<ArrayList<Record>> data) {
        File file;
        FileWriter fw;
        BufferedWriter bw;
        String fileName;
        int cont;

        for (int i = 0; i < data.size(); i++) {
            cont = 0;
            if (Record.header) {
                addCabecera(data.get(i));
                cont = -1;
            }
            fileName = "data_clarus_anom_" + (i + 1) + ".txt";
            file = new File(fileName);
            try {
                fw = new FileWriter(file);
                bw = new BufferedWriter(fw);
                for (Record r : data.get(i)) {
                    bw.write(r.toString());
                    bw.newLine();
                    cont++;
                }
                bw.close();
                fw.close();

                System.out.println("Records saved: " + cont);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }

    private static void addCabecera(ArrayList<Record> lista) {
        Record record;

        record = new Record(0);
        for (int i = 0; i < Record.listNames.size(); i++) {
            record.attrValues[i] = Record.listNames.get(i);
        }
        lista.add(0, record);
    }

}
