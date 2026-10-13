package com.zerotrust.risk.audit.redis;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** RESP2 fault fixture. Forwards only to QA6380; never modifies Redis operational configuration. */
final class RedisFaultProxy implements AutoCloseable {
    enum Mode { TIMEOUT_GET, HOLD_SCRIPT, DROP_COMMITTED_REPLY, INVALID_SCRIPT_RETURN }
    private static final Set<Integer> OWNED_PORTS = ConcurrentHashMap.newKeySet();
    private final ServerSocket listener;
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private final List<Socket> sockets = new CopyOnWriteArrayList<>();
    private final Mode mode;
    private final String prefix;
    private final AtomicBoolean armed = new AtomicBoolean();
    final CountDownLatch intercepted = new CountDownLatch(1);
    private final CountDownLatch release = new CountDownLatch(1);
    volatile String command;
    volatile String reply;
    volatile String scriptSha1;
    volatile Throwable failure;

    RedisFaultProxy(Mode mode, String prefix) throws IOException {
        this.mode = mode;
        this.prefix = prefix + ':';
        listener = new ServerSocket(0, 4, InetAddress.getByName(RedisAuditSupport.HOST));
        OWNED_PORTS.add(port());
        workers.submit(() -> {
            try { while (!listener.isClosed()) { Socket client = listener.accept(); sockets.add(client); workers.submit(() -> forward(client)); } }
            catch (IOException e) { if (!listener.isClosed()) failure = e; }
        });
    }
    int port() { return listener.getLocalPort(); }
    static boolean owns(int port) { return OWNED_PORTS.contains(port); }
    static int refusedEndpoint() throws IOException {
        try (ServerSocket reserved = new ServerSocket(0, 1, InetAddress.getByName(RedisAuditSupport.HOST))) {
            int port = reserved.getLocalPort(); OWNED_PORTS.add(port); return port;
        }
    }
    void arm() { armed.set(true); }
    void resume() { release.countDown(); }

    private void forward(Socket client) {
        try (client; Socket upstream = new Socket(RedisAuditSupport.HOST, RedisAuditSupport.QA_PORT)) {
            sockets.add(upstream);
            client.setSoTimeout(10000); upstream.setSoTimeout(10000);
            while (!client.isClosed()) {
                Frame request = read(client.getInputStream());
                @SuppressWarnings("unchecked") List<Frame> args = (List<Frame>) request.value;
                String name = args.get(0).text().toUpperCase(Locale.ROOT);
                guard(name, args);
                if (name.equals("EVALSHA")) scriptSha1 = args.get(1).text();
                if (armed.get() && mode == Mode.TIMEOUT_GET && name.equals("GET")) {
                    command = name; reply = "withheld-before-forward"; intercepted.countDown(); release.await(8, TimeUnit.SECONDS); return;
                }
                if (armed.get() && mode == Mode.HOLD_SCRIPT && name.startsWith("EVAL")) {
                    command = name; reply = "held-before-forward"; intercepted.countDown();
                    if (!release.await(8, TimeUnit.SECONDS)) throw new IOException("Fixture checkpoint timeout");
                }
                upstream.getOutputStream().write(request.wire);
                upstream.getOutputStream().flush();
                Frame response = read(upstream.getInputStream());
                if (armed.get() && name.startsWith("EVAL") && response.kind == ':' && ((Long) response.value) == 1L) {
                    command = name; reply = "Redis actual integer 1"; intercepted.countDown();
                    if (mode == Mode.DROP_COMMITTED_REPLY) return;
                    if (mode == Mode.INVALID_SCRIPT_RETURN) {
                        client.getOutputStream().write(":2\r\n".getBytes(StandardCharsets.US_ASCII)); client.getOutputStream().flush(); continue;
                    }
                }
                client.getOutputStream().write(response.wire);
                client.getOutputStream().flush();
            }
        } catch (EOFException | SocketException ignored) {
            // Expected connection teardown by client or injected loss.
        } catch (Throwable e) { if (!listener.isClosed()) failure = e; }
    }
    private void guard(String command, List<Frame> args) {
        if (!Set.of("AUTH", "PING", "INFO", "CLIENT", "SELECT", "GET", "EVAL", "EVALSHA", "QUIT").contains(command))
            throw new IllegalArgumentException("Proxy command forbidden: " + command);
        if (command.equals("AUTH") && (args.size() != 2 || !args.get(1).text().equals(System.getenv("QA_REDIS_PASSWORD"))))
            throw new IllegalArgumentException("Only the private QA credential may be forwarded");
        if (command.equals("SELECT") && !args.get(1).text().equals("0")) throw new IllegalArgumentException("Only DB0");
        if (command.equals("GET") && !args.get(1).text().startsWith(prefix)) throw new IllegalArgumentException("Unowned key");
        if (command.startsWith("EVAL")) {
            int count = Integer.parseInt(args.get(2).text());
            for (int i = 3; i < count + 3; i++) if (!args.get(i).text().startsWith(prefix)) throw new IllegalArgumentException("Unowned Lua key");
        }
    }
    private static Frame read(InputStream input) throws IOException {
        int kind = input.read(); if (kind < 0) throw new EOFException();
        ByteArrayOutputStream wire = new ByteArrayOutputStream(); wire.write(kind);
        String line = line(input, wire);
        Object value;
        switch (kind) {
            case '+', '-' -> value = line;
            case ':' -> value = Long.parseLong(line);
            case '$' -> {
                int length = Integer.parseInt(line);
                if (length < 0) value = null;
                else {
                    byte[] data = input.readNBytes(length + 2);
                    if (data.length != length + 2) throw new EOFException();
                    wire.write(data); value = Arrays.copyOf(data, length);
                }
            }
            case '*' -> {
                int length = Integer.parseInt(line);
                List<Frame> array = new ArrayList<>();
                for (int i = 0; i < length; i++) { Frame item = read(input); wire.write(item.wire); array.add(item); }
                value = array;
            }
            default -> throw new IOException("Unsupported RESP2 type " + kind);
        }
        return new Frame(kind, value, wire.toByteArray());
    }
    private static String line(InputStream input, ByteArrayOutputStream wire) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        while (true) {
            int b = input.read(); if (b < 0) throw new EOFException(); wire.write(b);
            if (b == '\r') { int lf = input.read(); if (lf != '\n') throw new IOException("Bad RESP line"); wire.write(lf); break; }
            result.write(b);
        }
        return result.toString(StandardCharsets.UTF_8);
    }
    private record Frame(int kind, Object value, byte[] wire) {
        String text() { return value instanceof byte[] b ? new String(b, StandardCharsets.UTF_8) : String.valueOf(value); }
    }
    @Override public void close() throws Exception {
        release.countDown(); listener.close();
        for (Socket socket : sockets) socket.close();
        workers.shutdownNow(); workers.awaitTermination(3, TimeUnit.SECONDS);
        OWNED_PORTS.remove(port());
    }
}
