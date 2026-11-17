package edu.atlas.shield.bench;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** Redraw the report charts from docs/bench/*.csv without re-measuring: ./mvnw test -Dgroups=bench -DexcludedGroups=none -Dtest=ChartsTest */
@Tag("bench")
class ChartsTest {
    @Test
    void redraw() { Charts.drawAll(); }
}
