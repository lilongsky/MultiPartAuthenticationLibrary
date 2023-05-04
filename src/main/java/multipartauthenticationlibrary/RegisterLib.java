package multipartauthenticationlibrary;



public class RegisterLib {
    public static String SMSOTPSender(String userPhoneNumber,
                                      String mailSever,int port, String senderAddress,String senderPsw){
        if (userPhoneNumber == null){
            return null;
        }
        try{
            String otp = String.format("%06d",SafeToolBox.SafetyRandomIntGenerator(6));
            String result;
            result = SMSOTP.sendOTP(otp,userPhoneNumber,mailSever,port,senderAddress,senderPsw);
            if (result.equals("true")) {
                return otp;
            }else return null;
        }catch (Exception e){
            return null;
        }
    }

    public static String EmailOTPSender(String userEmailAddress,
                                        String mailSever,int port, String senderAddress,String senderPsw){
        if (userEmailAddress == null){
            return null;
        }
        try {
            String otp = String.format("%06d",SafeToolBox.SafetyRandomIntGenerator(6));
            String result;
            result = EmailOTP.sendOTP(otp,userEmailAddress,mailSever,port,senderAddress,senderPsw);
            if (result.equals("true")) {
                return otp;
            }else return null;
        } catch (Exception e) {
            return null;
        }
    }

    public static String TOTPVerifier(String cCode, String TOTPToken) {
        try{
            if (cCode == null){
                return "empty Code";
            }
            String result = TOTP.TOTPVerifier(cCode,TOTPToken);
            if (result.equals("true")){
                return "true";
            }
            if (result.equals("WrongCode")){
                return "Wrong Code";
            }
        }catch (Exception e){
            return "500";
        }

        return "500";
    }

    public static String SMSOTPVerifier(String cCode,String sCode){

        return SMSOTP.verifyOTP(cCode,sCode);
    }

    public static String EmailOTPVerifier(String cCode,String sCode){

        return EmailOTP.verifyOTP(cCode,sCode);
    }

}
