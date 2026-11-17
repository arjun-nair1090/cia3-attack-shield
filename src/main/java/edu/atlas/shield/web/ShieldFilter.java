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
                    <!doctype html><meta name=viewport content="width=device-width, initial-scale=1"><title>Stopped</title>
                    <body style="margin:0;min-height:100vh;display:grid;place-items:center;background:#F2F5F7;color:#1E2630;font:18px/1.5 system-ui,sans-serif;padding:24px;box-sizing:border-box">
                    <main style="max-width:30rem">
                    <p style="display:inline-block;margin:0 0 18px;padding:6px 14px;border:4px solid #E8650A;color:#E8650A;font-weight:900;font-size:40px;letter-spacing:.02em;transform:rotate(-4deg)">Stopped</p>
                    <h1 style="margin:0 0 10px;font-size:26px">Attack Shield caught this request.</h1>
                    <p style="margin:0;color:#6B7A89">It matched a known attack pattern or came from a blocked address. Look at the projector: it is being taken apart there right now.</p>
                    </main>""");
            return;
        }
        chain.doFilter(req, res);
    }
}
