package multipartauthenticationlibrary;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.bouncycastle.util.encoders.Hex;

import java.security.NoSuchAlgorithmException;



public class LoginLib {

    public static String getUserNameFromRequest(HttpServletRequest request){

        return request.getParameter("username");
    }

    public static String CHAPRandomValueJsonGenerator(HttpServletRequest request) {

        HttpSession session = request.getSession();
        String loginRequestID = request.getParameter("id");

        String randomValue = new String((Hex.encode(SafeToolBox.SafetyRandomBytesGenerator(20))));
        String randomValueWithId;

        try {
             randomValueWithId = SafeToolBox.SHA256(loginRequestID + randomValue);//SH1
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        session.setAttribute("loginRequestIDandRan", randomValueWithId);
        session.setAttribute("cloginRequestID",loginRequestID);

        JsonObject obj = new JsonObject();
        obj.addProperty("id", loginRequestID);
        obj.addProperty("randomValue", randomValueWithId);
        GsonBuilder builder = new GsonBuilder();
        Gson gson = builder.create();
        return gson.toJson(obj);
    }

    public static String CHAPResult(HttpServletRequest request
            ,String susername,String spsw){

        String cusername = request.getParameter("username");
        String cResponse = request.getParameter("response");

        HttpSession session = request.getSession();
        String sLoginRequestID = (String) session.getAttribute("cloginRequestID");
        String sloginRequestIDandRan = (String) session.getAttribute("loginRequestIDandRan");
        String cLoginRequestID = request.getParameter("id");

        String correctResponse;
        if (sLoginRequestID.equals(cLoginRequestID)) {

            try {
                correctResponse = SafeToolBox.SHA256((spsw + sloginRequestIDandRan+sLoginRequestID));//SH2
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }

            if (cusername.equals(susername) && cResponse.equals(correctResponse)) {
                session.removeAttribute("loginRequestIDandRan");
                session.removeAttribute("cloginRequestID");

                session.setAttribute("isFirstAuthenticated","true");
                session.setAttribute("username",susername);

                session.setMaxInactiveInterval(1800);

                return "true";
            } else {
                return correctResponse;
            }
        }else {
            return "session id wrong";
        }
    }

    public static String PAPResult(HttpServletRequest request, String susername, String spsw){
        String cusername = request.getParameter("username");
        String cpsw = request.getParameter("response");
        HttpSession session = request.getSession();

        if ((cusername.equals(susername)) && cpsw.equals(spsw)){
            session.setAttribute("isFirstAuthenticated","true");
            session.setAttribute("username",susername);
            session.setMaxInactiveInterval(1800);
            return "true";
        }else{
            return "false";
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

    public static String EmailOTPVerifier(HttpServletRequest request,String sCode){

        String cCode = request.getParameter("EmailOTP");

        return EmailOTP.verifyOTP(cCode,sCode);
    }

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

    public static String SMSOTPVerifier(HttpServletRequest request,String sCode){


        String cCode = (String) request.getParameter("SMSOTP");

        return SMSOTP.verifyOTP(cCode,sCode);
    }

    public static String TOTPVerifier(HttpServletRequest request,String TOTPToken) {
        try{
            String cCode = (String) request.getParameter("TOTP");

            if ((cCode == null)||(cCode.equals(""))){
                return "empty Code";
            }
            String result = TOTP.TOTPVerifier(cCode,TOTPToken);
            if (result.equals("true")){
                return "true";
            }
            if (result.equals("WrongCode")){
                return "WrongCode";
            }
        }catch (Exception e){
            return "internal error";
        }
        return "internal error";
    }

    public static String[] BackUpCodeVerifier(HttpServletRequest request, String[] BackUpCode){
        String cCode = (String) request.getParameter("BackUpCode");
        String[] result = new String[2];
        if ((cCode == null)||(cCode.equals(""))) {
            result[0] = "empty Code";
            return result;
        }
        result[0] = BackUpOTP.verifyOTP(cCode,BackUpCode);
        result[1] = cCode;
        return result;
    }
}
