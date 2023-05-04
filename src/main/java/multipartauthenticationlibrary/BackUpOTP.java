package multipartauthenticationlibrary;


public class BackUpOTP {
    public static String[] GenerateOTP(int quantityOfOTP, int lengthOfOTP){
        String[] result= new String[quantityOfOTP];
        for (int i=0;i<quantityOfOTP;i++){
            result[i] = String.format(("%0"+lengthOfOTP+"d"), SafeToolBox.SafetyRandomIntGenerator(lengthOfOTP));
        }
        return result;
    }
    public static String verifyOTP(String cCode,String[] sCode){
        if (cCode == null) {
            return "empty Code";
        }
        for (String i:sCode){
            if (cCode.equals(i)) {
                return "true";
            }
        }
        return "WrongCode";
    }
}
