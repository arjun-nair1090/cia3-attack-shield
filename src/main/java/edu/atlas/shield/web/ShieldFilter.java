package edu.atlas.shield.web;

import edu.atlas.shield.core.Inspection;
import edu.atlas.shield.core.ShieldEngine;
import edu.atlas.shield.core.Verdict;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import org.springframework.web.util.UrlPathHelper;

import java.io.IOException;
import java.util.Set;

/** Every real HTTP request (the demo shop, scanner probes, anything) passes through the shield first. */
@Component
public class ShieldFilter extends OncePerRequestFilter {

    private final ShieldEngine engine;
    private final EventHub hub;

    public ShieldFilter(ShieldEngine engine, EventHub hub) {
        this.engine = engine;
        this.hub = hub;
    }

    private static final Set<String> DASHBOARD_FILES = Set.of("/", "/index.html", "/app.js", "/style.css", "/favicon.ico");

    /**
     * Inspect everything except the dashboard itself. The decision uses the decoded, normalized path the
     * dispatcher routes on, not the raw URI, so "/%73hop/search" cannot slip past as "not /shop".
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = UrlPathHelper.defaultInstance.getPathWithinApplication(request);
        return path.startsWith("/api/") || DASHBOARD_FILES.contains(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String raw = req.getRequestURI() + (req.getQueryString() == null ? "" : "?" + req.getQueryString());
        Inspection in = engine.inspect(req.getRemoteAddr(), raw);
        hub.publish("inspection", in);
        if (in.verdict() == Verdict.BLOCK) {
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.setContentType("text/html;charset=UTF-8");
            res.getWriter().write("""
                    <!doctype html><meta name=viewport content="width=device-width">
                    <body style="font:18px system-ui;background:#1a0606;color:#ffb4b4;display:grid;place-items:center;height:100vh;margin:0;text-align:center">
                    <div><div style="font-size:64px">&#x1F6E1;</div><h1>Blocked by Attack Shield</h1>
                    <p>This request matched a known attack. It is now on the live dashboard.</p></div>""");
            return;
        }
        chain.doFilter(req, res);
    }
}
