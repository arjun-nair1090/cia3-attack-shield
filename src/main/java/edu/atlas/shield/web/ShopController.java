package edu.atlas.shield.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.HtmlUtils;

/** The deliberately boring "victim" site the shield protects. */
@RestController
public class ShopController {

    @GetMapping("/shop")
    public RedirectView home() { return new RedirectView("/shop/index.html"); }

    @GetMapping(value = "/shop/product", produces = "text/html;charset=UTF-8")
    public String product(@RequestParam(defaultValue = "") String id) {
        return """
                <!doctype html><meta name=viewport content="width=device-width"><link rel=stylesheet href="/shop/shop.css">
                <main><a href="/shop/index.html">&larr; Campus Store</a><h1>Product #%s</h1><p>In stock.</p></main>"""
                .formatted(HtmlUtils.htmlEscape(id));
    }

    @GetMapping(value = "/shop/search", produces = "text/html;charset=UTF-8")
    public String search(@RequestParam(defaultValue = "") String q) {
        return """
                <!doctype html><meta name=viewport content="width=device-width"><link rel=stylesheet href="/shop/shop.css">
                <main><a href="/shop/index.html">&larr; Campus Store</a><h1>Results for "%s"</h1>
                <p>No products found. (The search is fake, the shield in front of it is real.)</p></main>"""
                .formatted(HtmlUtils.htmlEscape(q));
    }
}
