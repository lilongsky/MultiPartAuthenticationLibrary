package multipartauthenticationlibrary;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.security.NoSuchAlgorithmException;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;


public class LoginLib {
    private static ConcurrentHashMap<String,String> UsrEmailOTPCode = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<String,String> UsrSMSOTPCode = new ConcurrentHashMap<>();


    public static String RandomValueJsonResponder(HttpServletRequest request) {
        HttpSession session = request.getSession();
        String loginRequestID = request.getParameter("id");

        String randomValue = SafeToolBox.SafetyRandomValueGenerator(20);
        String randomValueWithId;
        try {
             randomValueWithId = SafeToolBox.SHA256(loginRequestID + randomValue);
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
                correctResponse = SafeToolBox.SHA256((spsw + sloginRequestIDandRan));
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

    public static String EmailOTPSender(String username,
                                        String userEmailAddress, String emailCodeToken, int emailCodeCounter,
                                        String mailSever,int port, String senderAddress,String senderPsw){
        try {
            String otp = SafeToolBox.HOTPCodeGenerator(emailCodeToken,emailCodeCounter);

            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.ssl.protocols", "TLSv1.2");
            props.put("mail.smtp.host", mailSever);
            props.put("mail.smtp.port", port);

            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                public PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(senderAddress, senderPsw);
                }
            });

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(senderAddress));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(userEmailAddress));
            message.setSubject("OTP Verification");
            message.setText("Your OTP is " + otp);
            Transport.send(message);
            UsrEmailOTPCode.putIfAbsent(username,otp);
            return "true";
        } catch (Exception e) {
            return null;
        }
    }

    public static String EmailOTPVerifier(HttpServletRequest request,String username){
        //

        String cCode = request.getParameter("EmailOTP");

        String sCode = UsrEmailOTPCode.get(username);
        if (cCode == null){
            return "empty Code";
        }
        if (sCode == null){
            return "no Code Sent";
        }
        if (cCode.equals(sCode)){
            return "true";
        }else {
            return "WrongCode";
        }
    }

    public static String SMSOTPSender(String username,
                                      String userEmailAddress, String phoneCodeToken, int phoneCodeCounter,
                                      String mailSever,int port, String senderAddress,String senderPsw){

        try{
            String otp = SafeToolBox.HOTPCodeGenerator(phoneCodeToken,phoneCodeCounter);

            //Currently using email instead for demo
                Properties props = new Properties();
                props.put("mail.smtp.auth", "true");
                props.put("mail.smtp.starttls.enable", "true");
                props.put("mail.smtp.ssl.protocols", "TLSv1.2");
                props.put("mail.smtp.host", mailSever);
                props.put("mail.smtp.port", port);

                Session session = Session.getInstance(props, new Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(senderAddress, senderPsw);
                    }
                });

                Message message = new MimeMessage(session);
                message.setFrom(new InternetAddress(senderAddress));
                message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(userEmailAddress));
                message.setSubject("OTP Verification");
                message.setText("Your OTP is " + otp);
                Transport.send(message);
            UsrSMSOTPCode.putIfAbsent(username,otp);
            return "true";
        }catch (Exception e){
            return null;
        }
    }

    public static String SMSOTPVerifier(HttpServletRequest request,String username){


        String cCode = (String) request.getParameter("SMSOTP");

        String sCode = UsrSMSOTPCode.get(username);
        if (cCode == null){
            return "empty Code";
        }
        if (sCode == null){
            return "no Code Sent";
        }
        if (cCode.equals(sCode)){
            return "true";
        }else {
            return "WrongCode";
        }
    }

    public static String TOTPVerifier(HttpServletRequest request,String TOTPToken) {
        try{
            String cCode = (String) request.getParameter("TOTP");

            String[] sCOde = SafeToolBox.TOTPCodeGenerator(TOTPToken);
            if (cCode == null){
                return "empty Code";
            }
            for (String i:sCOde) {
                if (i.equals(cCode)){
                    return "true";
                }
            }
            return "WrongCode";

        }catch (Exception e){
            return null;
        }

    }


}
