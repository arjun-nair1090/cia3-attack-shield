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

import java.io.IOException;

/** Every real HTTP request to the demo shop passes through the shield before it reaches the shop. */
@Component
public class ShieldFilter extends OncePerRequestFilter {

    private final ShieldEngine engine;
    private final EventHub hub;

    public ShieldFilter(ShieldEngine engine, EventHub hub) {
        this.engine = engine;
        this.hub = hub;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/shop");
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
