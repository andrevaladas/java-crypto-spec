package com.valadas.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;

public class ReadPassword {
    /**
     * Read a password from the InputStream "in".
     * <p>
     * As Strings are immutable, passwords should be stored as an array
     * of characters, which can be blanked out when no longer needed.
     * <p>
     * If the provided InputStream is the System's Console, this method
     * uses the non-echoing readPassword() method of java.io.Console
     * (new to JDK 6).  If not, a fallback implementation is used.
     * <p>
     * NOTE:  For expository purposes, and because some applications do
     * not understand multi-byte characters, only 8-bit ASCII passwords
     * are handled here.
     * <p>
     * NOTE:  If a SecurityManager is used, the default standard
     * java.policy file found in Sun's JDK (i.e.
     * <java-home>/lib/security/java.policy) allows reading the
     * line.separator property.  If your environment is different, this
     * code will need to be granted the appropriate privilege.
     *
     * @param   in
     *          the InputStream used to obtain the password.
     *
     * @return  A character array containing the password or passphrase,
     *          not including the line-termination characters,
     *          or null if an end of stream has been reached.
     *
     * @throws  IOException
     *          if an I/O problem occurs
     */
    public static final char[] readPassword(InputStream in)
            throws IOException {

        /*
         * If available, directly use the java.io.Console class to
         * avoid character echoing.
         */
        if (in == System.in && System.console() != null) {
            // readPassword returns "" if you just print ENTER,
            return System.console().readPassword();
        }

        /*
         * If a console is not available, read the InputStream
         * directly.  This approach may cause password echoing.
         *
         * Since different operating systems have different End-Of-Line
         * (EOL) sequences, this algorithm should allow for
         * platform-independent implementations.  Typical EOL sequences
         * are a single line feed ('\n'), or a carriage return/linefeed
         * combination ('\r\n').  However, some OS's use a single
         * a carriage return ('\r'), which complicates portability.
         *
         * Since we may not have the ability to push bytes back into the
         * InputStream, another approach is used here.  The javadoc for
         * java.lang.System.getProperties() specifies that
         * the set of system properties will contain a system-specific
         * value for the "line.separator".  Scan for this character
         * sequence instead of hard-coding a particular sequence.
         */
         
        /*
         * Enclose the getProperty in a doPrivileged block to minimize
         * the call stack permission required.
         */
        char [] EOL = AccessController.doPrivileged(
            new PrivilegedAction<char[]>() {
                public char[] run() {
                    String s = System.getProperty("line.separator");
                    // Shouldn't happen.
                    if (s == null) {
                        throw new RuntimeException(
                            "line.separator not defined");
                    }
                    return s.toCharArray();
                }
            });

        char [] buffer = new char[128];
        try {
            int len = 0;                // len of data in buffer.
            boolean done = false;       // found the EOL sequence
            int b;                      // byte read

            while (!done) {
                /*
                 * realloc if necessary
                 */
                if (len >= buffer.length) {
                    char [] newbuffer = new char[len + 128];
                    System.arraycopy(buffer, 0, newbuffer, 0, len);
                    Arrays.fill(buffer, ' ');
                    buffer = newbuffer;
                }

                /*
                 * End-of-Stream?
                 */
                if ((b = in.read()) == -1) {
                    // Return as much as we have, null otherwise.
                    if (len == 0) {
                        return null;
                    }
                    break;
                } else {
                    /*
                     * NOTE:  In the simple PBE example here,
                     * only 8 bit ASCII characters are handled.
                     */
                    buffer[len++] = (char) b;
                }

                /*
                 * check for the EOL sequence.  Do we have enough bytes?
                 */
                if (len >= EOL.length) {
                    int i = 0;
                    for (i = 0; i < EOL.length; i++) {
                        if (buffer[len - EOL.length + i] != EOL[i]) {
                            break;
                        }
                    }
                    done = (i == EOL.length);
                }
            }

            /*
             * If we found the EOL, strip the EOL chars.
             */
            char [] result = new char[done ? len - EOL.length : len];
            System.arraycopy(buffer, 0, result, 0, result.length);

            return result;
        } finally {
            /*
             * Zero out the buffer.
             */
            if (buffer != null) {
                Arrays.fill(buffer, ' ');
            }
        }
    }
}