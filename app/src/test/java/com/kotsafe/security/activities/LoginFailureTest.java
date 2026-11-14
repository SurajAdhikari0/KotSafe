package com.kotsafe.security.activities;

import com.google.firebase.FirebaseNetworkException;
import com.google.firebase.FirebaseTooManyRequestsException;
import com.google.firebase.auth.FirebaseAuthException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import android.app.Application;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(application=Application.class, sdk=33, manifest=Config.NONE)
public class LoginFailureTest {
    @Test public void unknownAccountAndWrongPasswordGetTheSameSignupHint() {
        String message = LoginActivity.authError(new FirebaseAuthException("ERROR_WRONG_PASSWORD", "fixture"), "");
        assertTrue(message.contains("Sign up"));
        assertEquals(message, LoginActivity.authError(new FirebaseAuthException("ERROR_USER_NOT_FOUND", "fixture"), ""));
    }

    @Test public void outagesAndThrottlingDoNotCountAsBadPasswords() {
        Exception network = new FirebaseNetworkException("fixture");
        Exception limit = new FirebaseTooManyRequestsException("fixture");
        assertFalse(LoginActivity.invalidCredentials(network));
        assertFalse(LoginActivity.invalidCredentials(limit));
        assertTrue(LoginActivity.authError(network, "").contains("connection"));
        assertTrue(LoginActivity.authError(limit, "").contains("later"));
    }
}
