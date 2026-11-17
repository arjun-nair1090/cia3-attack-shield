package edu.atlas.shield.web;

import edu.atlas.shield.algo.MaxFlow;
import edu.atlas.shield.core.Inspection;
import edu.atlas.shield.core.ShieldEngine;
import edu.atlas.shield.core.TrafficSimulator;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    private final ShieldEngine engine;
    private final TrafficSimulator simulator;
    private final EventHub hub;

    public ApiController(ShieldEngine engine, TrafficSimulator simulator, EventHub hub) {
        this.engine = engine;
        this.simulator = simulator;
        this.hub = hub;
    }

    @GetMapping("/events")
    public SseEmitter events() { return hub.subscribe(); }

    @GetMapping("/stats")
    public ShieldEngine.Stats stats() { return engine.stats(); }

    /** Raw Bloom filter bits as little-endian 64-bit words (about 170 KB), for the bit-field view. */
    @GetMapping(value = "/bloom/bits", produces = "application/octet-stream")
    public byte[] bloomBits() {
        long[] words = engine.bloomWords();
        ByteBuffer buf = ByteBuffer.allocate(words.length * Long.BYTES).order(ByteOrder.LITTLE_ENDIAN);
        buf.asLongBuffer().put(words);
        return buf.array();
    }

    /** Shop URLs on every active IPv4 LAN interface, so the dashboard can show a scan-to-attack QR code. */
    @GetMapping("/info")
    public Map<String, Object> info(HttpServletRequest req) throws SocketException {
        List<String> urls = new ArrayList<>();
        for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!nic.isUp() || nic.isLoopback() || nic.isVirtual()) continue;
            for (InetAddress a : Collections.list(nic.getInetAddresses()))
                if (a instanceof Inet4Address && a.isSiteLocalAddress())
                    urls.add("http://" + a.getHostAddress() + ":" + req.getLocalPort() + "/shop/index.html");
        }
        return Map.of("shopUrls", urls);
    }

    @GetMapping("/traffic")
    public ShieldEngine.TrafficWindow traffic(@RequestParam(defaultValue = "60") int seconds) {
        return engine.traffic(seconds);
    }

    /** "Block me": adds only the caller's own address, so nobody can lock someone else out. */
    @PostMapping("/blocklist")
    public Map<String, Object> blockMe(HttpServletRequest req) {
        String ip = req.getRemoteAddr();
        return Map.of("ip", ip, "added", engine.addBadIp(ip));
    }

    public record InspectRequest(String text, String ip) {}

    /**
     * "What would the shield do with this?" Runs the real pipeline on any pasted URL, header or payload,
     * without counting it into the live stats. ip is optional; given, it goes through the Bloom + exact check.
     */
    @PostMapping("/inspect")
    public Inspection inspect(@RequestBody InspectRequest body) {
        if (body.text() == null || body.text().isEmpty()) throw new IllegalArgumentException("text is required");
        if (body.text().length() > 8_192) throw new IllegalArgumentException("text is too long (max 8192 characters, the size of a request line)");
        String ip = body.ip() == null || body.ip().isBlank() ? null : body.ip().strip();
        if (ip != null && !ShieldEngine.isIp(ip)) throw new IllegalArgumentException("not an IP address: " + ip);
        return engine.analyze(ip, body.text());
    }

    public record SimulateRequest(int requests, double attackRatio, Long seed) {}

    @PostMapping("/simulate")
    public TrafficSimulator.Result simulate(@RequestBody SimulateRequest body) {
        long seed = body.seed() == null ? System.nanoTime() : body.seed();
        TrafficSimulator.Result r = simulator.run(body.requests(), body.attackRatio(), seed, in -> hub.publish("inspection", in));
        hub.publish("simulation", r);
        return r;
    }

    public record Link(String from, String to, long capacity) {}
    public record Network(List<String> nodes, List<Link> links, String source, String sink) {}
    public record Bottleneck(long maxFlow, List<Link> minCut, List<String> sourceSide) {}

    @PostMapping("/bottleneck")
    public Bottleneck bottleneck(@RequestBody Network net) {
        if (net.nodes() == null || net.links() == null) throw new IllegalArgumentException("nodes and links are required");
        if (net.nodes().size() > 500 || net.links().size() > 5_000) throw new IllegalArgumentException("network too large (max 500 nodes, 5000 links)");
        Map<String, Integer> id = new HashMap<>();
        for (String n : net.nodes()) {
            if (n == null || n.isBlank()) throw new IllegalArgumentException("node names must be non-empty");
            if (id.putIfAbsent(n, id.size()) != null) throw new IllegalArgumentException("duplicate node: " + n);
        }
        MaxFlow g = new MaxFlow(id.size());
        for (Link l : net.links()) {
            if (l == null) throw new IllegalArgumentException("links must not contain null");
            g.addEdge(node(id, l.from()), node(id, l.to()), l.capacity());
        }
        MaxFlow.Result r = g.solve(node(id, net.source()), node(id, net.sink()));
        List<Link> cut = r.minCut().stream()
                .map(e -> new Link(net.nodes().get(e.from()), net.nodes().get(e.to()), e.capacity())).toList();
        List<String> side = new ArrayList<>();
        for (int i = 0; i < r.sourceSide().length; i++) if (r.sourceSide()[i]) side.add(net.nodes().get(i));
        return new Bottleneck(r.maxFlow(), cut, side);
    }

    private static int node(Map<String, Integer> id, String name) {
        Integer i = id.get(name);
        if (i == null) throw new IllegalArgumentException("unknown node: " + name);
        return i;
    }

    @ExceptionHandler({IllegalArgumentException.class, IndexOutOfBoundsException.class})
    public ResponseEntity<Map<String, String>> badRequest(RuntimeException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }

    /** Missing or malformed JSON body: same {error} shape as every other 400, not Spring's default page. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> unreadable() {
        return ResponseEntity.badRequest().body(Map.of("error", "request body is missing or is not valid JSON"));
    }
}
