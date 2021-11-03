package ca.ubc.cs.cs317.dnslookup;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.IntStream;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL_NS = 10;
    private static final int MAX_QUERY_ATTEMPTS = 3;
    protected static final int SO_TIMEOUT = 5000;

    private final DNSCache cache = DNSCache.getInstance();
    private final Random random = new SecureRandom();
    private final DNSVerbosePrinter verbose;
    private final DatagramSocket socket;
    private InetAddress nameServer;

    /**
     * Creates a new lookup service. Also initializes the datagram socket object with a default timeout.
     *
     * @param nameServer The nameserver to be used initially. If set to null, "root" or "random", will choose a random
     *                   pre-determined root nameserver.
     * @param verbose    A DNSVerbosePrinter listener object with methods to be called at key events in the query
     *                   processing.
     * @throws SocketException      If a DatagramSocket cannot be created.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public DNSLookupService(String nameServer, DNSVerbosePrinter verbose) throws SocketException, UnknownHostException {
        this.verbose = verbose;
        socket = new DatagramSocket();
        socket.setSoTimeout(SO_TIMEOUT);
        this.setNameServer(nameServer);
    }

    /**
     * Returns the nameserver currently being used for queries.
     *
     * @return The string representation of the nameserver IP address.
     */
    public String getNameServer() {
        return this.nameServer.getHostAddress();
    }

    /**
     * Updates the nameserver to be used in all future queries.
     *
     * @param nameServer The nameserver to be used initially. If set to null, "root" or "random", will choose a random
     *                   pre-determined root nameserver.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public void setNameServer(String nameServer) throws UnknownHostException {

        // If none provided, choose a random root nameserver
        if (nameServer == null || nameServer.equalsIgnoreCase("random") || nameServer.equalsIgnoreCase("root")) {
            List<ResourceRecord> rootNameServers = cache.getCachedResults(cache.rootQuestion, false);
            nameServer = rootNameServers.get(0).getTextResult();
        }
        this.nameServer = InetAddress.getByName(nameServer);
    }

    /**
     * Closes the lookup service and related sockets and resources.
     */
    public void close() {
        socket.close();
    }

    /**
     * Finds all the result for a specific node. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are included in the results as CNAME records (i.e., not queried further).
     *
     * @param question Host and record type to be used for search.
     * @return A (possibly empty) set of resource records corresponding to the specific query requested.
     */
    public Collection<ResourceRecord> getDirectResults(DNSQuestion question) {

        Collection<ResourceRecord> results = cache.getCachedResults(question, true);
        if (results.isEmpty()) {
            iterativeQuery(question, nameServer);
            results = cache.getCachedResults(question, true);
        }
        return results;
    }

    /**
     * Finds all the result for a specific node. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are retrieved recursively for new records of the same type, and the returning set will contain both the
     * CNAME record and the resulting addresses.
     *
     * @param question             Host and record type to be used for search.
     * @param maxIndirectionLevels Number of CNAME indirection levels to support.
     * @return A set of resource records corresponding to the specific query requested.
     * @throws CnameIndirectionLimitException If the number CNAME redirection levels exceeds the value set in
     *                                        maxIndirectionLevels.
     */
    public Collection<ResourceRecord> getRecursiveResults(DNSQuestion question, int maxIndirectionLevels)
            throws CnameIndirectionLimitException {

        if (maxIndirectionLevels < 0) throw new CnameIndirectionLimitException();

        Collection<ResourceRecord> directResults = getDirectResults(question);
        if (directResults.isEmpty() || question.getRecordType() == RecordType.CNAME)
            return directResults;

        List<ResourceRecord> newResults = new ArrayList<>();
        for (ResourceRecord record : directResults) {
            newResults.add(record);
            if (record.getRecordType() == RecordType.CNAME) {
                newResults.addAll(getRecursiveResults(
                        new DNSQuestion(record.getTextResult(), question.getRecordType(), question.getRecordClass()),
                        maxIndirectionLevels - 1));
            }
        }
        return newResults;
    }

    /**
     * Retrieves DNS results from a specified DNS server using the iterative mode. After an individual query is sent and
     * its response is received (or times out), checks if an answer for the specified host exists. Resulting values
     * (including answers, nameservers and additional information provided by the nameserver) are added to the cache.
     * <p>
     * If after the first query an answer exists to the original question (either with the same record type or an
     * equivalent CNAME record), the function returns with no further actions. If there is no answer after the first
     * query but the response returns at least one nameserver, a follow-up query for the same question must be done to
     * another nameserver. Note that nameservers returned by the response contain text records linking to the host names
     * of these servers. If at least one nameserver provided by the response to the first query has a known IP address
     * (either from this query or from a previous query), it must be used first, otherwise additional queries are
     * required to obtain the IP address of the nameserver before it is queried. Only one nameserver must be contacted
     * for the follow-up query.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the first query.
     */
    protected void iterativeQuery(DNSQuestion question, InetAddress server) {
        String hostName = question.getHostName();
        int typeCode = question.getRecordType().getCode();
        int classCode = question.getRecordClass().getCode();
        InetAddress ipAddress = nameServer;

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        try {
            // Building a DNS question
            buildQuestionHeader(dos);
            buildQuestionSection(hostName, typeCode, classCode, dos);

            byte[] out_buf = baos.toByteArray();

            // Send the question
            DatagramPacket out_packet = new DatagramPacket(out_buf, out_buf.length, nameServer, DEFAULT_DNS_PORT);
            socket.send(out_packet);

            // Await response from DNS server
            byte[] in_buf = new byte[1024];
            DatagramPacket in_packet = new DatagramPacket(in_buf, in_buf.length);
            socket.receive(in_packet);

            int bytes_received = in_packet.getLength();

            // Inputstream makes it easier to read bytes
            DataInputStream din = new DataInputStream(new ByteArrayInputStream(in_buf));
            for (int i = 0; i < bytes_received; i++) {
                System.out.print(String.format("%02X", in_buf[i]));
            }
            System.out.println("\n");

            int queryId = din.readShort();
            int flags = din.readShort();
            int num_questions = din.readShort();
            int num_answer_rrs = din.readShort();
            int num_auth_rrs = din.readShort();
            int num_additional_rrs = din.readShort();

//            System.out.println("Transaction ID: 0x" + String.format("%x", queryId));
//            System.out.println("Flags: 0x" + String.format("%x", flags));
//            System.out.println("Questions: 0x" + String.format("%x", num_questions));
            System.out.println("Answers RRs: " + String.format("%d", num_answer_rrs));
            System.out.println("Authority RRs: " + String.format("%d", num_auth_rrs));
            System.out.println("Additional RRs: " + String.format("%d", num_additional_rrs));

            // Read bytes from question to move offset
            int record_length = 0;
            List<String> records = new ArrayList<>();
            while ((record_length = din.readByte()) > 0) {
                // If record length is not 0, then we read bytes into a record
                byte[] record = new byte[record_length];

                for (int i = 0; i < record_length; i++) {
                    record[i] = din.readByte();
                }

                records.add(new String(record, "UTF-8"));
            }

            int questionRecordType = din.readShort();
            int questionRecordClass = din.readShort();

//            System.out.println("Question Record Type: 0x" + String.format("%x", questionRecordType));
//            System.out.println("Question Record Class: 0x" + String.format("%x", questionRecordClass));


            if (num_answer_rrs > 0 || num_auth_rrs > 0 || num_additional_rrs > 0) {
                int total_records = num_answer_rrs + num_auth_rrs + num_additional_rrs;

                for (int i = 0; i < total_records; i++) {
                    int recordNameOffset = din.readShort();
                    int recordType = din.readShort();
                    int recordClass = din.readShort();
                    int ttl = din.readInt();

                    int data_length = din.readShort();
                    byte[] byteResult = new byte[data_length];

                    int string_length = 0;
                    String recordstring = "";
                    while ((string_length = din.readByte() & 0xff) > 0) {
                        recordstring += ".";
                        byte[] stringbuf = new byte[512];
                        if (string_length >= 192) {
                            // Compression - points to somewhere else...
                            int pointer = (string_length - 192) + (din.readByte() & 0xff);
                            int target_length = in_buf[pointer];
                            for (int j = 0; j < target_length + pointer; j++) {
                                stringbuf[j] = in_buf[j+pointer];
                            }
                        } else {
                            for (int j = 0; j < string_length; j++) {
                                stringbuf[j] = din.readByte();
                            }
                        }
                        recordstring += new String(stringbuf, "UTF-8");
                    }

                    System.out.println("GOT RECORD " + recordstring);

                    ResourceRecord record;

                    // handle record type
                    switch (recordType) {
                        case 1: // A - InetAddress
//                            InetAddress addressResult = InetAddress.getByAddress(byteResult);
//                            record = new ResourceRecord(question, ttl, addressResult);
//                            System.out.println("Address: " + new String(byteResult, "US-ASCII"));
//                            System.out.println("got address: " + addressResult.getAddress());
                            break;
                        case 2: // NS - string
                        case 15: // MX - string
                        case 16: // TXT - string???
                        case 5: // CNAME - string
//                            System.out.println(recordType);
//                            String result = byteArrayToHexString(byteResult);
//                            record = new ResourceRecord(question, ttl, result);
//                            System.out.println("Record: " + new String(byteResult, "US-ASCII"));
//                            System.out.println("got record: " + result);
                            break;
                        case 3: // MD - ?
                        case 4: // MF - ?
                        case 6: // SOA - ?
                        case 7: // MB - ?
                        case 8: // MG - ?
                        case 9: // MR - ?
                        case 10: // NULL - ?
                        case 11: // WKS - ?
                        case 12: // PTR - ?
                        case 13: // HINFO - ?
                        case 14: // MINFO - ?
                            break;
                    }

                }

            }

//            int recordNameOffset = din.readShort();
//            int recordType = din.readShort();
//            int recordClass = din.readShort();
//            int TTL = din.readInt();
//            short addrLen = din.readShort();
//            String address = new String(din.readNBytes(addrLen));
//
//            System.out.println("Len: 0x" + String.format("%x", addrLen));
//
//            System.out.print("Address: " + address);

//            for (int i = 0; i < addrLen; i++ ) {
//                System.out.print("" + String.format("%d", (din.readByte() & 0xFF)) + ".");
//            }
            System.out.println("\n");
            System.out.println("--end--\n");
            System.out.println("\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void buildQuestionSection(String hostName, int typeCode, int classCode, DataOutputStream dos) throws IOException {
        // Split string into parts by "."
        String[] domainParts = hostName.split("\\.");

        for (int i = 0; i<domainParts.length; i++) {
            byte[] domainBytes = domainParts[i].getBytes("UTF-8");
            // first byte signals the length of this part of the hostname
            dos.writeByte(domainBytes.length);
            // then we write that many bytes, corresponding to that part of the hostname
            dos.write(domainBytes);
        }

        // 0x00 signals no more parts of hostname remaining
        dos.writeByte(0x00);

        // Next comes type eg. A = 0x01
        dos.writeShort(typeCode);

        // Then finally class eg. IN = 0x01
        dos.writeShort(classCode);
    }

    private void buildQuestionHeader(DataOutputStream dos) throws IOException {
        // Identifier: server will copy ID into response so it can be matched to a query.
        // TODO: randomly generate this.
        dos.writeShort(0x1234);

        // Write Query Flags.
        // QR, Opcode, AA, TC, RD, RA = 0, for standard iterative query, the rest is 0
        dos.writeShort(0x0000);

        // Question Count: Number of questions in the Question section. Default to 1
        dos.writeShort(0x0001);

        // Answer Record Count: Number of RRs in the Answer section. Question has 0
        dos.writeShort(0x0000);

        // Authority Record Count: Number of RRs in the Authority section. Question has 0
        dos.writeShort(0x0000);

        // Additional Record Count: Number of RRs in the Additional section. Question has 0
        dos.writeShort(0x0000);
    }

    /**
     * Handles the process of sending an individual DNS query to a single question. Builds and sends the query (request)
     * message, then receives and parses the response. Received responses that do not match the requested transaction ID
     * are ignored. If no response is received after SO_TIMEOUT milliseconds, the request is sent again, with the same
     * transaction ID. The query should be sent at most MAX_QUERY_ATTEMPTS times, after which the function should return
     * without changing any values. If a response is received, all of its records are added to the cache.
     * <p>
     * The method verbose.printQueryToSend() must be called every time a new query message is about to be sent.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the query.
     * @return If no response is received, returns null. Otherwise, returns a set of resource records for all
     * nameservers received in the response. Only records found in the nameserver section of the response are included,
     * and only those whose record type is NS. If a response is received but there are no nameservers, returns an empty
     * set.
     */
    protected Set<ResourceRecord> individualQueryProcess(DNSQuestion question, InetAddress server) {

        /* TO BE COMPLETED BY THE STUDENT */
        return null;
    }

    /**
     * Fills a ByteBuffer object with the contents of a DNS query. The buffer must be updated from the start (position
     * 0). A random transaction ID must also be generated and filled in the corresponding part of the query. The query
     * must be built as an iterative (non-recursive) request for a regular query with a single question. When the
     * function returns, the buffer's position (`queryBuffer.position()`) must be equivalent to the size of the query
     * data.
     *
     * @param queryBuffer The ByteBuffer object where the query will be saved.
     * @param question    Host name and record type/class to be used for the query.
     * @return The transaction ID used for the query.
     */
    protected int buildQuery(ByteBuffer queryBuffer, DNSQuestion question) {

        /* TO BE COMPLETED BY THE STUDENT */
        return 0;
    }

    /**
     * Parses and processes a response received by a nameserver. Adds all resource records found in the response message
     * to the cache. Calls methods in the verbose object at appropriate points of the processing sequence. Must be able
     * to properly parse records of the types: A, AAAA, NS, CNAME and MX (the priority field for MX may be ignored). Any
     * other unsupported record type must create a record object with the data represented as a hex string (see method
     * byteArrayToHexString).
     *
     * @param responseBuffer The ByteBuffer associated to the response received from the server.
     * @return A set of resource records for all nameservers received in the response. Only records found in the
     * nameserver section of the response are included, and only those whose record type is NS. If there are no
     * nameservers, returns an empty set.
     */
    protected Set<ResourceRecord> processResponse(ByteBuffer responseBuffer) {

        /* TO BE COMPLETED BY THE STUDENT */
        return null;
    }

    /**
     * Helper function that converts a hex string representation of a byte array. May be used to represent the result of
     * records that are returned by the nameserver but not supported by the application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    private static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }

    public static class CnameIndirectionLimitException extends Exception {
    }
}
