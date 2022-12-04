
package hashingfunction;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Cryptogenic Hashing function:
 *
 * In this class we will use PBKDF2,
 * to encrypt users password
 *
 * This function will be intentionally made slow, to make it withstand brute
 * force attacks.
 *
 * @author jake
 */
public class HashingFunction {

    /**
     * @param password: it is the user's password that will be hashed
     * @param salt: a random string that mixes up a password's hash,
     * so if two users has the same password the two hashes won't be the same
     * @param iteration: the number of iterations, it determinates how slow the hash function will be,
     * but be careful if the number of iterations is too high,
     * it will use too much resources on the server. It should be around 10000 - 100000
     * @param keylength: required output length of the hash function. 256 or 512 keyLength is safe
     *
     * @return key
     * @throws Exception
     */
    public static String hash(String password, byte[] salt, int iteration, int keylength) throws Exception {

        String hashedPassword = "";

        if (password == null || password.length() == 0)
            throw new IllegalArgumentException("Empty password");
        if (iteration > 100000 || iteration < 10000)
            throw new IllegalArgumentException("Iteration should be in range (10000-100000)");
        if (keylength != 256 && keylength != 512)
            throw new IllegalArgumentException("Keylength is not safe");

        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = f.generateSecret(new PBEKeySpec(password.toCharArray(), salt, iteration, keylength));

        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Creating random salt to prevent attacks,
     * from rainbow table
     * @return salt
     */
    public static byte[] randomSalt() {
        byte[] salt = new byte[16];
        SecureRandom secure_random = new SecureRandom();
        secure_random.nextBytes(salt);
        return salt;
    }

    /**
     * Use this method if you don't want to use
     * randomSalt()
     *
     * @param salt
     * @return
     */
    public static byte[] getSalt(String salt) {
        return salt.getBytes();
    }

    // checks if entered password matches with hashed password
    public static void checkPassword(String password, String hashedPassword, byte[] salt, int iteration, int keylength) throws Exception {
        if (hashedPassword.equals(hash(password, salt, iteration, keylength)))
            System.out.println("Password Matched!");
        else
            System.out.println("Password Didn't Match!");
    }

    /**
     * @param args the command line arguments
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception {

        final int ITERATION = 15000;
        final int KEY_LENGTH = 256;

        String password = "jakespassword1234";
        byte[] randSalt = randomSalt();

        String hashedKey = hash(password, randSalt, ITERATION, KEY_LENGTH);
        System.out.println("Your password is hashed to : " + hashedKey);

        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter your password : ");
        String enterPassword = scanner.next();

        checkPassword(enterPassword, hashedKey, randSalt, ITERATION, KEY_LENGTH);

    }

}
