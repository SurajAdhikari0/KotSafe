/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KotSafe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KotSafe.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.kotsafe.security.model;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BankingOverlayGuardTest {

    @Test
    public void testIsFinancialApp_KnownApps() {
        BankingOverlayGuard guard = BankingOverlayGuard.getInstance();

        // UPI & Indian Banking
        assertTrue(guard.isFinancialApp("com.phonepe.app"));
        assertTrue(guard.isFinancialApp("net.one97.paytm"));
        assertTrue(guard.isFinancialApp("in.org.npci.upiapp"));
        assertTrue(guard.isFinancialApp("com.sbi.lotusintouch"));
        assertTrue(guard.isFinancialApp("com.hdfcbank.mobilebanking"));

        // Global Banking
        assertTrue(guard.isFinancialApp("com.chase.sig.android"));
        assertTrue(guard.isFinancialApp("com.infonow.bofa"));
        assertTrue(guard.isFinancialApp("com.revolut.revolut"));
        assertTrue(guard.isFinancialApp("com.paypal.android.p2pmobile"));

        // Crypto Wallets & Exchanges
        assertTrue(guard.isFinancialApp("com.binance.dev"));
        assertTrue(guard.isFinancialApp("com.coinbase.android"));
        assertTrue(guard.isFinancialApp("io.metamask"));
        assertTrue(guard.isFinancialApp("com.wallet.crypto.trustapp"));

        // Heuristic Matches
        assertTrue(guard.isFinancialApp("com.custom.international.banking"));
        assertTrue(guard.isFinancialApp("org.secure.crypto.coldwallet"));

        // Non-financial Apps MUST return false
        assertFalse(guard.isFinancialApp("com.whatsapp"));
        assertFalse(guard.isFinancialApp("com.google.android.youtube"));
        assertFalse(guard.isFinancialApp("com.android.chrome"));
        assertFalse(guard.isFinancialApp("com.facebook.katana"));
    }
}

