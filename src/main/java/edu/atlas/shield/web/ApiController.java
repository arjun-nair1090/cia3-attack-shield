package edu.atlas.shield.web;

import edu.atlas.shield.algo.MaxFlow;
import edu.atlas.shield.core.ShieldEngine;
import edu.atlas.shield.core.TrafficSimulator;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.ArrayList;
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
        for (Link l : net.links()) g.addEdge(node(id, l.from()), node(id, l.to()), l.capacity());
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
}
