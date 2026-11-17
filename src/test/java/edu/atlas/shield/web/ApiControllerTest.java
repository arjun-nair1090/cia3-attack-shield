package edu.atlas.shield.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.net.URI;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The REST layer end to end: real filters, real engine, every invalid input answered with a 400 and a reason. */
@SpringBootTest
@AutoConfigureMockMvc
class ApiControllerTest {

    @Autowired MockMvc mvc;

    private static final RequestPostProcessor FROM_PHONE = r -> { r.setRemoteAddr("192.168.1.50"); return r; };

    private static MockHttpServletRequestBuilder json(String path, String body) {
        return post(path).contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static String net(String links) {
        return """
                {"nodes":["s","a","t"],"links":[%s],"source":"s","sink":"t"}""".formatted(links);
    }

    @Test
    void bottleneckFindsMaxFlowAndMinCut() throws Exception {
        mvc.perform(json("/api/bottleneck", net("""
                        {"from":"s","to":"a","capacity":10},{"from":"a","to":"t","capacity":4}""")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.maxFlow").value(4))
                .andExpect(jsonPath("$.minCut[0].from").value("a"))
                .andExpect(jsonPath("$.sourceSide", contains("s", "a")));
    }

    @Test
    void bottleneckOnDisconnectedNetworkIsZeroNotAnError() throws Exception {
        mvc.perform(json("/api/bottleneck", net("""
                        {"from":"s","to":"a","capacity":10}""")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.maxFlow").value(0))
                .andExpect(jsonPath("$.minCut", hasSize(0)));
    }

    @Test
    void bottleneckRejectsEveryKindOfBadNetwork() throws Exception {
        String max = String.valueOf(Long.MAX_VALUE);
        String[][] cases = {
                {net("""
                        {"from":"s","to":"t","capacity":%s},{"from":"s","to":"t","capacity":%s}""".formatted(max, max)), "max flow exceeds"},
                {net("null"), "null"},
                {net("""
                        {"from":"s","to":"nowhere","capacity":1}"""), "unknown node: nowhere"},
                {net("""
                        {"from":"s","to":"t","capacity":-5}"""), "capacity"},
                {"""
                        {"nodes":["s","s"],"links":[],"source":"s","sink":"s"}""", "duplicate node"},
                {"""
                        {"nodes":["s","t"],"links":[],"source":"s","sink":"s"}""", "must differ"},
                {"""
                        {"links":[]}""", "required"},
                {"{not json", "not valid JSON"},
        };
        for (String[] c : cases)
            mvc.perform(json("/api/bottleneck", c[0]))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error", containsString(c[1])));
    }

    @Test
    void simulateMeasuresDetectionAndValidatesParameters() throws Exception {
        mvc.perform(json("/api/simulate", """
                        {"requests":500,"attackRatio":0.5,"seed":7}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requests").value(500))
                .andExpect(jsonPath("$.detectionRate", greaterThan(0.9)));
        mvc.perform(json("/api/simulate", """
                        {"requests":0,"attackRatio":0.5}""")).andExpect(status().isBadRequest());
        mvc.perform(json("/api/simulate", """
                        {"requests":10,"attackRatio":1.5}""")).andExpect(status().isBadRequest());
        mvc.perform(json("/api/simulate", "")).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", containsString("missing")));
    }

    @Test
    void trafficRejectsOutOfRangeWindows() throws Exception {
        mvc.perform(get("/api/traffic?seconds=60")).andExpect(status().isOk()).andExpect(jsonPath("$.all", hasSize(60)));
        mvc.perform(get("/api/traffic?seconds=0")).andExpect(status().isBadRequest());
        mvc.perform(get("/api/traffic?seconds=601")).andExpect(status().isBadRequest());
        mvc.perform(get("/api/traffic?seconds=abc")).andExpect(status().isBadRequest());
    }

    @Test
    void dashboardApiIsLocalOnlyButAnyoneMayBlockThemselves() throws Exception {
        mvc.perform(get("/api/stats").with(FROM_PHONE)).andExpect(status().isForbidden());
        mvc.perform(json("/api/simulate", "{\"requests\":1,\"attackRatio\":0}").with(FROM_PHONE)).andExpect(status().isForbidden());
        mvc.perform(post("/api/blocklist").with(r -> { r.setRemoteAddr("198.51.100.23"); return r; }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ip").value("198.51.100.23"))
                .andExpect(jsonPath("$.added").value(true));
    }

    @Test
    void shopRequestsAreInspectedEvenWhenThePathIsEncoded() throws Exception {
        // Real query strings, as a browser sends them (MockMvc's .param() would leave getQueryString() empty).
        mvc.perform(get(URI.create("/shop/search?q=%27+or+1%3D1--"))).andExpect(status().isForbidden());
        mvc.perform(get(URI.create("/shop/search?q=running+shoes"))).andExpect(status().isOk());
        // Regression: "/%73hop" decodes to "/shop"; it must not slip past the filter as "not a shop path".
        mvc.perform(get(URI.create("/%73hop/search?q=%3Cscript%3E"))).andExpect(status().isForbidden());
    }
}
