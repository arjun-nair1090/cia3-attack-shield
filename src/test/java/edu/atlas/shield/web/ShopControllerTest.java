package edu.atlas.shield.web;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ShopControllerTest {

    private final ShopController shop = new ShopController();

    @Test
    void searchFindsByNameAndCategory() {
        assertTrue(shop.search("calculator").contains("1 result for"));
        assertTrue(shop.search("hoodie").contains("2 results for")); // the lab coat "fits over a hoodie"
        assertTrue(shop.search("STATIONERY").contains("3 results for"));
    }

    @Test
    void searchEscapesWhateverIsTyped() {
        String html = shop.search("<img src=x onerror=alert(1)>");
        assertFalse(html.contains("<img src=x"));
        assertTrue(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assertTrue(html.contains("Nothing matches"));
    }

    @Test
    void emptySearchListsEverything() {
        String html = shop.search("   ");
        assertTrue(html.contains("All products"));
        assertEquals(ShopController.CATALOG.size(), html.split("class=\"item\"").length - 1);
    }

    @Test
    void unknownOrMalformedProductIs404() {
        assertEquals(404, shop.product("999").getStatusCode().value());
        assertEquals(404, shop.product("1 or 1=1").getStatusCode().value());
        assertEquals(404, shop.product("").getStatusCode().value());
        assertEquals(200, shop.product("1").getStatusCode().value());
    }

    @Test
    void cartHandlesMissingAndBogusItems() {
        assertTrue(shop.cart("2").contains("Lab notebook, A4"));
        assertTrue(shop.cart("abc").contains("Your bag is empty"));
    }
}
