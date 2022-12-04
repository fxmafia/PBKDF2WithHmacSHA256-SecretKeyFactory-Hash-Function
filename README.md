# PBKDF2WithHmacSHA256-SecretKeyFactory-Hash-Function
PBKDF2WithHmacSHA256  - Secret Key Factory  - Hash Functions

Demonstration challenge

Your hash function has 4 arguments: password, salt, iteration, keylength.

password: it is the user's password that will be hashed
salt: a random string that mixes up a password's hash, so if two users has the same password the two hashes won't be the same
iteration: the number of iterations, it determinates how slow the hash function will be, but be careful if the number of iterations is too high, it will use too much resources on the server. It should be around 10000 - 100000
keylength: required output length of the hash function. 256 or 512 keyLength is safe.


Step 0:
You need to check whether the password argument is empty:
public static String hash(String password, byte[] salt, int iteration, int keylength) throws Exception{
    if (password == null || password.length() == 0)
        throw new IllegalArgumentException("Empty password");	
}



Step 1:
Instantiate a SecretKeyFactory object that converts secret keys of the
specified algorithm, in our tutorial it is PBKDF2WithHmacSHA256
public static String hash(String password, byte[] salt, int iteration, int keylength) throws Exception{
    if (password == null || password.length() == 0)
        throw new IllegalArgumentException("Empty password");
    SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
}


Step 2:
Generate a SecretKey object from the provided key specification
public static String hash(String password, byte[] salt, int iteration, int keylength) throws Exception{
    if (password == null || password.length() == 0)
        throw new IllegalArgumentException("Empty password");
    SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    SecretKey key = f.generateSecret(new PBEKeySpec(password.toCharArray(), salt.getBytes(), iteration, keylength));
}



Step 3:
Return with the generated hash. It is a byte[], so you need to convert it to String type as the following code shows:
public static String hash(String password, String salt, int iteration, int keylength) throws Exception{
    if (password == null || password.length() == 0)
        throw new IllegalArgumentException("Empty password");
    SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    SecretKey key = f.generateSecret(new PBEKeySpec(password.toCharArray(), salt.getBytes(), iteration, keylength));
    return Base64.getEncoder().encodeToString(key.getEncoded());
}
