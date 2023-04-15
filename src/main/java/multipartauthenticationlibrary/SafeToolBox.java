package multipartauthenticationlibrary;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.NoSuchAlgorithmException;

public class SafeToolBox {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static byte[] longToBytes(long l) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE / 8);
        buffer.putLong(l);
        return buffer.array();
    }



    public static String SHA256(String message) throws NoSuchAlgorithmException {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        return new String (Hex.encode(hash));
    }

    public static String SafetyRandomValueGenerator(int lengthOfByte){
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[lengthOfByte];
        random.nextBytes(bytes);
        return new String(Hex.encode(bytes));
    }

    public static String HOTPCodeGenerator(String token, long counter ) throws NoSuchAlgorithmException, NoSuchProviderException {
        try {
            byte[] tokenByte = Base32.decode(token);
            byte[] counterByte = longToBytes(counter);

            Mac mac = Mac.getInstance("HmacSHA256", "BC");
            mac.init(new SecretKeySpec(tokenByte,"RAW"));
            byte[] hmac = mac.doFinal(counterByte);

            int offset = hmac[hmac.length - 1] & 0xf;// get last 4 bit
            int binary = ((hmac[offset] & 0x7f) << 24) |
                    ((hmac[offset + 1] & 0xff) << 16) |
                    ((hmac[offset + 2] & 0xff) << 8) |
                    (hmac[offset + 3] & 0xff);
            // base on offset get 6 Byte and reorganize to 32 bit long binary number
            // //7f to remove the highest bit avoid negative number

            int otp = binary % 1000000;
            return String.format("%06d", otp);
        }catch (Exception e){
            return null;
        }
    }

    public static String[] TOTPCodeGenerator(String token)throws NoSuchAlgorithmException, NoSuchProviderException{
        long timeStamp = System.currentTimeMillis() / 1000;
        int timeStep = (int)(timeStamp / 30);
        String[] acceptedTOTPCode = new String[3];
        for (int i=-1; i < 2; i = i+1){
            acceptedTOTPCode[i+1]= HOTPCodeGenerator(token,(timeStep+i));
        }
        return acceptedTOTPCode;
    }
}
