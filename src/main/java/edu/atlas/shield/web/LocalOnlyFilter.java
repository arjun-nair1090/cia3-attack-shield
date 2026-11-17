package edu.atlas.shield.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UrlPathHelper;

import java.io.IOException;
import java.net.InetAddress;

/**
 * The dashboard API (live feed with visitors' IPs, flood launcher, stats) answers only the machine running
 * the server. Other devices may attack the shop and block themselves, nothing else.
 * Set shield.dashboard.local-only=false to show the dashboard on a second screen.
 */
@Component
public class LocalOnlyFilter extends OncePerRequestFilter {

    private final boolean localOnly;

    public LocalOnlyFilter(@Value("${shield.dashboard.local-only:true}") boolean localOnly) {
        this.localOnly = localOnly;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = UrlPathHelper.defaultInstance.getPathWithinApplication(request);
        return !localOnly || !path.startsWith("/api/") || path.equals("/api/blocklist");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        // getRemoteAddr() is always an IP literal, so this never triggers a DNS lookup.
        if (!InetAddress.getByName(req.getRemoteAddr()).isLoopbackAddress()) {
            res.sendError(HttpServletResponse.SC_FORBIDDEN, "dashboard API is local-only");
            return;
        }
        chain.doFilter(req, res);
    }
}
