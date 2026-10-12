/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.kotsafe.security.model.ScanModeConfig;
import com.kotsafe.security.model.ScanModeConfig.TrustAction;
import com.kotsafe.security.model.ScanModeConfig.TrustScoreConfig;

import org.junit.Test;

public class TrustScoreConfigTest {

    @Test
    public void testInvariantsValid() {
        // Valid default operating point: quarantine 42 < warning 78, FPR 0.40% <= 0.50%
        TrustScoreConfig.validateInvariants(78, 42, 0.0040f);
    }

    @Test(expected = IllegalStateException.class)
    public void testInvariantsInvertedThresholdsThrows() {
        // Inverted: quarantine 85 >= warning 78
        TrustScoreConfig.validateInvariants(78, 85, 0.0040f);
    }

    @Test(expected = IllegalStateException.class)
    public void testInvariantsEqualThresholdsThrows() {
        // Equal thresholds
        TrustScoreConfig.validateInvariants(78, 78, 0.0040f);
    }

    @Test(expected = IllegalStateException.class)
    public void testInvariantsExcessiveFprThrows() {
        // FPR exceeds 0.50% budget
        TrustScoreConfig.validateInvariants(78, 42, 0.0085f);
    }

    @Test
    public void testEvaluateTrustSemantics() {
        // Higher score = more trusted
        // >= 78 => PASS
        assertEquals(TrustAction.PASS, TrustScoreConfig.evaluateTrust(100));
        assertEquals(TrustAction.PASS, TrustScoreConfig.evaluateTrust(85));
        assertEquals(TrustAction.PASS, TrustScoreConfig.evaluateTrust(78));

        // 42 <= score < 78 => WARNING
        assertEquals(TrustAction.WARNING, TrustScoreConfig.evaluateTrust(77));
        assertEquals(TrustAction.WARNING, TrustScoreConfig.evaluateTrust(60));
        assertEquals(TrustAction.WARNING, TrustScoreConfig.evaluateTrust(42));

        // < 42 => QUARANTINE
        assertEquals(TrustAction.QUARANTINE, TrustScoreConfig.evaluateTrust(41));
        assertEquals(TrustAction.QUARANTINE, TrustScoreConfig.evaluateTrust(20));
        assertEquals(TrustAction.QUARANTINE, TrustScoreConfig.evaluateTrust(0));
    }
}
