package multipartauthenticationlibrary;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.*;


import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import java.security.SecureRandom;
import java.security.Security;
import java.security.NoSuchAlgorithmException;

public class SafeToolBox {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String SHA256(String message) throws NoSuchAlgorithmException {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        return new String (Hex.encode(hash));
    }

    public static byte[] SafetyRandomBytesGenerator(int lengthOfByte){
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[lengthOfByte];
        random.nextBytes(bytes);
        return bytes;
    }

    public static int SafetyRandomIntGenerator(int lengthOfInt){
        byte[] bytes= SafetyRandomBytesGenerator(lengthOfInt);
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        int result = (buffer.getInt()) & (Integer.MAX_VALUE);
        return result = (int) (result % Math.pow(10,lengthOfInt));
    }
}
