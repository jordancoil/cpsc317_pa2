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

    private boolean currentlyCaching = true;
    private int noResponseCount = 0;

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
        realIter(question, server, server);
    }

    protected void realIter(DNSQuestion question, InetAddress server, InetAddress originalServer) {
        var nsWrapper = new Object() {
            InetAddress nextNameServer = null;
        };


        // first query
        Set<ResourceRecord> nameServers = individualQueryProcess(question, server);
        List<ResourceRecord> results = cache.getCachedResults(question, true);
        if (results.isEmpty()) {
            Iterator<ResourceRecord> nameServerIter = nameServers.iterator();

            while (nameServerIter.hasNext() && nsWrapper.nextNameServer == null) {
                ResourceRecord next = nameServerIter.next();
                String nostName = next.getTextResult();

                cache.forEachRecord((q, r) -> {
                    String qostName = q.getHostName();
                    if (nostName.equals(qostName) && r.getRecordType().getCode() == 1) {
                        InetAddress ipAddress = r.getInetResult();
                        if (ipAddress != null) {
                            nsWrapper.nextNameServer = ipAddress;
                        }
                    }
                });

                if (nsWrapper.nextNameServer != null) {
                    break;
                }
            }

            if (nsWrapper.nextNameServer == null) {
                // Didnt find anything that had an IP
                Iterator<ResourceRecord> newNameServerIter = nameServers.iterator();
                while (newNameServerIter.hasNext() && nsWrapper.nextNameServer == null) {
                    ResourceRecord next = newNameServerIter.next();
                    String nostName = next.getTextResult();

                    // Try to get IP for nameserver
                    DNSQuestion newIP = new DNSQuestion(nostName, RecordType.getByCode(1), RecordClass.getByCode(1));
                    realIter(newIP, originalServer, originalServer);

                    cache.forEachRecord((q, r) -> {
                        String qostName = q.getHostName();
                        if (nostName.equals(qostName)) {
                            InetAddress ipAddress = r.getInetResult();
                            if (ipAddress != null) {
                                nsWrapper.nextNameServer = ipAddress;
                            }
                        }
                    });

                    if (nsWrapper.nextNameServer != null) {
                        break;
                    }
                }
            }

            realIter(question, nsWrapper.nextNameServer, originalServer);
        } else {
            return;
        }
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
        try {
            ByteBuffer queryBuffer = ByteBuffer.allocate(1024);
            int tId = buildQuery(queryBuffer, question);
            DatagramPacket out_packet = new DatagramPacket(queryBuffer.array(), queryBuffer.position(), server, DEFAULT_DNS_PORT);
            verbose.printQueryToSend(question, server, tId);
            socket.send(out_packet);

            ByteBuffer responseBuffer = ByteBuffer.allocate(1024);
            DatagramPacket in_packet = new DatagramPacket(responseBuffer.array(), responseBuffer.limit());

            try {
                socket.receive(in_packet);
            } catch (SocketTimeoutException e1) {
                // resend 1
                socket.send(out_packet);
                try {
                    socket.receive(in_packet);
                } catch (SocketTimeoutException e2) {
                    // resend 2
                    socket.send(out_packet);
                    try {
                        socket.receive(in_packet);
                    } catch (SocketTimeoutException e3) {
                        return null;
                    }
                }
            }


            return processResponse(responseBuffer);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

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
        // Building Header
        // Transaction ID
        short randomShort = (short) random.nextInt(Short.MAX_VALUE + 1);
        queryBuffer.putShort(randomShort);
        // Query Flags
        queryBuffer.putShort((short) 0x0000); // QR, Opcode, AA, TC, RD, RA = 0, for standard iterative query, the rest is 0
        queryBuffer.putShort((short) 0x0001); // Question Count: Number of questions in the Question section. Default to 1
        queryBuffer.putShort((short) 0x0000); // Answer Record Count: Number of RRs in the Answer section. Question has 0
        queryBuffer.putShort((short) 0x0000); // Authority Record Count: Number of RRs in the Authority section. Question has 0
        queryBuffer.putShort((short) 0x0000); // Additional Record Count: Number of RRs in the Additional section. Question has 0

        // Building Question Section
        String hostName = question.getHostName();
        String[] domainParts = hostName.split("\\.");
        try {
            for (int i = 0; i<domainParts.length; i++) {
                byte[] domainBytes = new byte[0];
                domainBytes = domainParts[i].getBytes("UTF-8");

                queryBuffer.put((byte) domainBytes.length); // first byte signals the length of this part of the hostname
                queryBuffer.put(domainBytes); // then we write that many bytes, corresponding to that part of the hostname
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        int typeCode = question.getRecordType().getCode();
        int classCode = question.getRecordClass().getCode();

        queryBuffer.put((byte) 0x00); // 0x00 signals no more parts of hostname remaining
        queryBuffer.putShort((short) typeCode); // Next comes type eg. A = 0x01
        queryBuffer.putShort((short) classCode); // Then finally class eg. IN = 0x01
        return randomShort;
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
        Set<ResourceRecord> result = new HashSet<>();

        byte[] responseBytes = responseBuffer.array();
        StringBuilder sb = new StringBuilder();
        for (byte b : responseBytes) {
            sb.append(String.format("%02X ", b));
        }
//        System.out.println(sb.toString()); // TESTING

        int transactionId = responseBuffer.getShort();
        int flags = responseBuffer.getShort();
        int num_questions = responseBuffer.getShort();
        int num_answer_rrs = responseBuffer.getShort();
        int num_auth_rrs = responseBuffer.getShort();
        int num_additional_rrs = responseBuffer.getShort();

        int errorCodeMask = 0x000f;
        int errorCode = (flags & errorCodeMask);

        int authoritativeMask = 0x0400;
        int authoritativeBit = (flags & authoritativeMask) >> 10;
        boolean authoritative = authoritativeBit > 0;

        verbose.printResponseHeaderInfo(transactionId, authoritative, errorCode);

        // Read bytes from question to move offset
        int record_length = 0;
        String prefix = "";
        StringBuffer questionStringBuf = new StringBuffer();
        while ((record_length = responseBuffer.get()) > 0) {
            // If record length is not 0, then we read bytes into a record
            questionStringBuf.append(prefix);
            byte[] questionpart = new byte[record_length];

            for (int i = 0; i < record_length; i++) {
                questionpart[i] = responseBuffer.get();
            }

            prefix = ".";
            questionStringBuf.append(new String(questionpart));
        }

        int questionRecordType = responseBuffer.getShort();
        int questionRecordClass = responseBuffer.getShort();
        String hostname = questionStringBuf.toString();
        DNSQuestion question = new DNSQuestion(hostname, RecordType.getByCode(questionRecordType), RecordClass.getByCode(questionRecordClass));
//        System.out.println(questionStringBuf.toString()); // FOR TESTING
//        System.out.println("Question Record Type: 0x" + String.format("%x", questionRecordType));
//        System.out.println("Question Record Class: 0x" + String.format("%x", questionRecordClass));

        verbose.printAnswersHeader(num_answer_rrs);

        for (int i = 0; i < num_answer_rrs; i++) {
            readRecordFromBuffer(responseBuffer, result);
        }

        verbose.printNameserversHeader(num_auth_rrs);

        for (int i = 0; i < num_auth_rrs; i++) {
            readRecordFromBuffer(responseBuffer, result);
        }

        verbose.printAdditionalInfoHeader(num_additional_rrs);

        for (int i = 0; i < num_additional_rrs; i++) {
            readRecordFromBuffer(responseBuffer, result);
        }

        return result;
    }

    private void readRecordFromBuffer(ByteBuffer responseBuffer, Set<ResourceRecord> nameservers) {
        StringBuffer recordNameBuf = new StringBuffer();
        readName(responseBuffer, recordNameBuf, "", responseBuffer.position(), true);
        String recordNameString = recordNameBuf.toString();

        int recordType = responseBuffer.getShort();
        int recordClass = responseBuffer.getShort();
        DNSQuestion recordsQuestion = new DNSQuestion(recordNameString, RecordType.getByCode(recordType), RecordClass.getByCode(recordClass));

        int ttl = responseBuffer.getInt();
        int recordLength = responseBuffer.getShort(); // DO NOT MOVE/DELETE, needed to move offset
        ByteBuffer byteResult = ByteBuffer.allocate(512);
        byte[] realResult;
        ResourceRecord record = null;
        int recordPartlength = 0;
        String recordPrefix = "";
        switch (recordType) {
            case 1:  // A
            case 28: // AAAA
                for (int i = 0; i < recordLength; i++) {
                    byteResult.put(responseBuffer.get());
                }

                realResult = Arrays.copyOfRange(byteResult.array(), 0, recordLength);

                try {
                    InetAddress addressResult = InetAddress.getByAddress(realResult);
                    record = new ResourceRecord(recordsQuestion, ttl, addressResult);
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                }
//                String result = recordStringBuf.toString();

                break;
            case 2:  // NS
            case 5:  // CNAME
            case 15: // MX
                while ((recordPartlength = responseBuffer.get() & 0xff) > 0) {
                    if (recordPartlength >= 192) {
                        // Compression - points to somewhere else...
                        int targetIndex = (recordPartlength - 192) + (responseBuffer.get() & 0xff);

                        int length = 0;
                        int i = targetIndex;
                        while((length = responseBuffer.get(i)) > 0) {
                            i++; // since we need to move the length.
                            byteResult.put(recordPrefix.getBytes());

                            for (int j = 0; j < length; j++) {
                                byteResult.put(responseBuffer.get(i+j));
                            }
                            recordPrefix = ".";
                            i += length;
                        }
                        break; // pointer signals end.
                    } else {
                        byteResult.put(recordPrefix.getBytes());
                        for (int i = 0; i < recordPartlength; i++) {
                            byteResult.put(responseBuffer.get());
                        }
                    }
                    recordPrefix = ".";
                }

                realResult = new byte[byteResult.position()];
                realResult = Arrays.copyOfRange(byteResult.array(), 0, realResult.length);

                record = new ResourceRecord(recordsQuestion, ttl, new String(realResult));
                break;
            default:
                while ((recordPartlength = responseBuffer.get() & 0xff) > 0) {
                    if (recordPartlength >= 192) {
                        // Compression - points to somewhere else...
                        int targetIndex = (recordPartlength - 192) + (responseBuffer.get() & 0xff);

                        int length = 0;
                        int i = targetIndex;
                        while((length = responseBuffer.get(i)) > 0) {
                            i++; // since we need to move the length.
                            byteResult.put(recordPrefix.getBytes());

                            for (int j = 0; j < length; j++) {
                                byteResult.put(responseBuffer.get(i+j));
                            }
                            recordPrefix = ".";
                            i += length;
                        }
                        break; // pointer signals end.
                    } else {
                        byteResult.put(recordPrefix.getBytes());
                        for (int i = 0; i < recordPartlength; i++) {
                            byteResult.put(responseBuffer.get());
                        }
                    }
                    recordPrefix = ".";
                }

                realResult = new byte[byteResult.position()];
                realResult = Arrays.copyOfRange(byteResult.array(), 0, realResult.length);

                record = new ResourceRecord(recordsQuestion, ttl, byteArrayToHexString(realResult));
                break;
        }

        verbose.printIndividualResourceRecord(record, recordType, recordClass);

        if (this.currentlyCaching) {
            cache.addResult(record);
        }

        if (recordType == 2) {
            // NS
            nameservers.add(record);
        }
    }

    private void readName(ByteBuffer responseBuffer, StringBuffer strBuf, String prefix, int pos, boolean movePos) {
        int firstByte = responseBuffer.get(pos);
        int isPointerMask = 0xC0;
        int pointerMask = 0x3FFF;
        if ((firstByte & isPointerMask) >> 6 == 3) {
            // This name is somewhere else...
            int pointer = responseBuffer.getShort(pos) & pointerMask;
            if (movePos) {
                responseBuffer.position(pos + 2);
            }
            readName(responseBuffer, strBuf, prefix, pointer, false);
        } else {
            // This name is here!
            int length = 0;
            int i = pos;
            while((length = responseBuffer.get(i)) > 0) {
                i++;
                strBuf.append(prefix);
                byte[] namePart = new byte[length];
                for (int j = 0; j < length; j++) {
                    namePart[j] = responseBuffer.get(i+j);
                }
                strBuf.append(new String(namePart));
                prefix = ".";
                i += length;
                if (movePos) {
                    responseBuffer.position(i);
                }
            }
            if ((length & isPointerMask) >> 6 == 3) {
                // The rest of this name is somewhere else...
                int pointer = responseBuffer.getShort(i) & pointerMask;
                if (movePos) {
                    responseBuffer.position(pos + 2);
                }
                readName(responseBuffer, strBuf, prefix, pointer, false);
            }
        }
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
