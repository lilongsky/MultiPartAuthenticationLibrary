package multipartauthenticationlibrary;


import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;


public class TOTP {
    private static byte[] longToBytes(long l) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE / 8);
        buffer.putLong(l);
        return buffer.array();
    }
    public static String HOTPCodeGenerator(String token, long counter ) throws NoSuchAlgorithmException, NoSuchProviderException {
        try {
            Base32 base32 = new Base32();
            byte[] tokenByte = base32.decode(token);
            byte[] counterByte = longToBytes(counter);

            Mac mac = Mac.getInstance("HmacSHA1", "BC");
            mac.init(new SecretKeySpec(tokenByte,"RAW"));
            byte[] hmac = mac.doFinal(counterByte);

            int offset = hmac[hmac.length - 1] & 0xf;// get last 4 bit
            int binary = ((hmac[offset] & 0x7f) << 24) |
                    ((hmac[offset + 1] & 0xff) << 16) |
                    ((hmac[offset + 2] & 0xff) << 8) |
                    (hmac[offset + 3] & 0xff);
            // base on offset get 4 Byte and reorganize to 32 bit long binary number
            // //7f to remove the highest bit avoid negative number

            int otp = binary % 1000000;
            return String.format("%06d", otp);
        }catch (Exception e){
            return null;
        }
    }
    public static String TOTPVerifier(String code,String token)throws NoSuchAlgorithmException, NoSuchProviderException{
        long timeStamp = System.currentTimeMillis() / 1000;
        long timeStep = timeStamp / 30;
        String[] acceptedTOTPCode = new String[3];
        for (int i=-1; i < 2; i = i+1){
            acceptedTOTPCode[i+1]= HOTPCodeGenerator(token,(timeStep+i));
        }
        for (String i:acceptedTOTPCode){
            if (i.equals(code)){
                return "true";
            }
        }
        return "WrongCode";
    }


    public static String TOTPTokenGenerator(){
        Base32 base32 = new Base32();
        String token;
        token = new String(base32.encode(SafeToolBox.SafetyRandomBytesGenerator(16)));
        token = token.replaceAll("=+$","");
        return token;
    }

    public static String TOTPUrlGenerator(String username, String issuer,String token){
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",issuer,username,token,issuer);
    }
}
